"""`mine` 生成器 —— 从「指纹 + 会话 + 答案」拼出完整的 4 步请求。

纯函数、不联网，便于离线自测；联网拿会话的是 client.py。

    seed = generate.session_from_gt2(pk, site, gt2_resp)   # 真 gt2
    obj  = generate.build_mine(seed, fp, pem, answers=[0,2,1], ua=...)
    json.dump(obj, open("mine.json","w"))
"""
from __future__ import annotations

import json
import random
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from . import crypto, hash as ahash

DEFAULT_SURL = "client-api.arkoselabs.com"
UA_DEFAULT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36")
FORM_CT = "application/x-www-form-urlencoded; charset=UTF-8"


def _api(surl: str) -> str:
    return f"https://{surl}"


@dataclass
class SessionSeed:
    public_key: str
    site: str
    token_full: str = ""
    sid: str = ""
    game_token: str = ""
    challenge_id: str = ""
    blob: Optional[str] = None
    resp_gt2: Dict = field(default_factory=dict)
    resp_gfct: Dict = field(default_factory=dict)

    @property
    def token_base(self) -> str:
        return self.token_full.split("|", 1)[0]


def session_from_gt2(public_key: str, site: str, resp: dict) -> SessionSeed:
    tok = str(resp.get("token", ""))
    return SessionSeed(
        public_key=public_key, site=site, token_full=tok,
        sid=str(resp.get("session_id", "") or resp.get("sid", "")),
        blob=resp.get("blob"), resp_gt2=resp,
    )


def apply_gfct(seed: SessionSeed, resp: dict) -> SessionSeed:
    seed.resp_gfct = resp
    seed.game_token = str(resp.get("game_token", "") or resp.get("gameToken", ""))
    seed.challenge_id = str(resp.get("challengeID", "") or resp.get("challenge_id", ""))
    return seed


# ---------------------------------------------------------------------------
def new_fingerprint(*, ua: str = UA_DEFAULT, lang: str = "zh-CN",
                    width: int = 1920, height: int = 1080, **extra) -> dict:
    """生成一份最小但自洽的指纹（f/n/wh 都算好）。"""
    fe = [au_ver(ua), 8, False, False, True, lang, "Win32", width, height,
          "Asia/Shanghai", 480, 1, 0, lang, False, False, "", "0,0"]
    fp = {
        "api_type": "js",
        "f": ahash.fp_fe_digest(fe, "x86"),
        "n": ahash.b64_unix_seconds(),
        "wh": ahash.wh_digest(["navigator", "location", "document", "indexedDB"],
                              ["Window", "EventTarget", "Object"]),
        "enhanced_fp": {
            "user_agent_data_mobile": False,
            "navigator_languages": lang,
            "screen_pixel_depth": 24,
            "window_inner_width": width,
            "window_inner_height": height - 133,
            "window_outer_width": width,
            "window_outer_height": height,
            "navigator_device_memory": 8,
            "headless_browser_selenium": False,
            "headless_browser_phantom": False,
            "browser_detection_firefox": False,
            "browser_detection_brave": False,
        },
        "fe": fe,
        "ife_hash": ahash.murmur3_x86_128(b"arke" + b"|".join(
            str(x).encode() for x in fe))[:16],
        "jsbd": json.dumps({"ac": 1, "cd": 2}, separators=(",", ":")),
    }
    fp["enhanced_fp"].update(extra)
    return fp


def au_ver(ua: str) -> str:
    for part in ua.split():
        if part.startswith("Chrome/"):
            return part.split("/", 1)[1]
    return ""


def reseal(fp: dict) -> dict:
    """重算 f / n，避免指纹与 fe / 时间不自洽。"""
    fp = dict(fp)
    if "fe" in fp:
        fp["f"] = ahash.fp_fe_digest(fp["fe"], "x86")
    if not fp.get("n"):
        fp["n"] = ahash.b64_unix_seconds()
    return fp


# ---------------------------------------------------------------------------
def client_hints(ua: str) -> Dict[str, str]:
    """真实 Chrome 在 POST 上必发的 Client Hints（实测真机 gt2 请求带这三个）。"""
    import re as _re
    m = _re.search(r"Chrome/(\d+)", ua or "")
    v = m.group(1) if m else "155"
    return {
        "sec-ch-ua": f'"Google Chrome";v="{v}", "Chromium";v="{v}", "Not(A:Brand";v="24"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
    }


def _hdr(ua: str, *, origin: Optional[str] = None, referer: Optional[str] = None,
         extra: Optional[dict] = None,
         accept_language: str = "en-US,en;q=0.9") -> Dict[str, str]:
    h = {
        "content-type": FORM_CT,
        "accept": "*/*",
        "user-agent": ua,
        "accept-language": accept_language,
    }
    h.update(client_hints(ua))
    if origin:
        h["origin"] = origin
        h["referer"] = referer or (origin + "/")
    if extra:
        h.update(extra)
    return h


def build_gt2(fp: dict, pem: str, *, public_key: str, site: str, ua: str = UA_DEFAULT,
              style_theme: str = "default", capi_mode: str = "lightbox",
              blob: Optional[str] = None, now_ms: Optional[int] = None,
              surl: str = DEFAULT_SURL, field: str = "c",
              fingerprint_override: Optional[str] = None,
              capi_version: Optional[str] = None,
              language: str = "currentLanguage",
              ark_build_id: str = "9fdbbdc3-859f-44ba-8334-229c279a79f1",
              accept_language: str = "en-US,en;q=0.9") -> dict:
    ms = now_ms if now_ms is not None else int(time.time() * 1000)
    if fingerprint_override is not None:
        fp_blob = fingerprint_override
    else:
        fp_plain = {k: v for k, v in reseal(fp).items() if k != "c"}
        fp_blob = crypto.arkose_encrypt_fp(fp_plain, pem)
    body = {
        "public_key": public_key, "capi_mode": capi_mode,
        "style_theme": style_theme, "rnd": f"{random.random():.16f}",
        field: fp_blob, "site": site, "userbrowser": ua,
        "language": language,
        "data[blob]": blob if blob is not None else "undefined",
    }
    if capi_version:
        body["capi_version"] = capi_version
    headers = _hdr(ua, origin=site, referer=site + "/",
                   extra={"x-ark-esync-value": str(crypto.arkose_esync_timestamp(ms))},
                   accept_language=accept_language)
    if ark_build_id:
        headers["ark-build-id"] = ark_build_id
    return {
        "stage": "gt2",
        "url": f"{_api(surl)}/fc/gt2/public_key/{public_key}",
        "headers": headers,
        "body": body,
    }


def build_gfct(seed: SessionSeed, ua: str = UA_DEFAULT, *, lang: str = "zh",
               render_type: str = "canvas", api_breaker: str = "1.6.0",
               analytics_tier: str = "40", now_ms: Optional[int] = None,
               surl: str = DEFAULT_SURL) -> dict:
    ms = now_ms if now_ms is not None else int(time.time() * 1000)
    return {
        "stage": "gfct",
        "url": f"{_api(surl)}/fc/gfct/",
        "headers": _hdr(ua, extra={
            "x-newrelic-timestamp": crypto.newrelic_timestamp(ms)}),
        "body": {
            "token": seed.token_base, "sid": seed.sid, "lang": lang,
            "render_type": render_type, "isAudioGame": "false",
            "is_compatibility_mode": "false", "apiBreakerVersion": api_breaker,
            "analytics_tier": analytics_tier,
        },
    }


def build_ca(seed: SessionSeed, answers_it, *, tguess_plain: str,
             requested_id_plain: str = '{"sc":[376,345]}',
             bio_plain: Optional[str] = None, ua: str = UA_DEFAULT,
             render_type: str = "canvas", analytics_tier: str = "40",
             now_ms: Optional[int] = None, surl: str = DEFAULT_SURL) -> dict:
    """answers_it: 单轮答案，[0,2] 或 [{"index":0},...]。"""
    ms = now_ms if now_ms is not None else int(time.time() * 1000)
    tok = seed.token_base
    if answers_it and isinstance(answers_it[0], dict):
        guess_obj = list(answers_it)
    else:
        guess_obj = [{"index": int(i)} for i in answers_it]
    bio = bio_plain if bio_plain is not None else json.dumps(
        {"mm": [[1, 1]], "mc": len(guess_obj)}, separators=(",", ":"))
    return {
        "stage": "ca",
        "url": f"{_api(surl)}/fc/ca/",
        "headers": _hdr(ua, extra={
            "x-newrelic-timestamp": crypto.newrelic_timestamp(ms),
            "x-requested-id": crypto.cryptojs_encrypt(
                requested_id_plain, crypto.requested_id_key(tok)),
        }),
        "body": {
            "session_token": tok,
            "game_token": seed.game_token,
            "guess": crypto.cryptojs_encrypt(
                json.dumps(guess_obj, separators=(",", ":")), tok),
            "tguess": crypto.cryptojs_encrypt(tguess_plain, tok),
            "bio": crypto.cryptojs_encrypt(bio, tok),
            "render_type": render_type, "analytics_tier": analytics_tier,
            "is_compatibility_mode": "false",
        },
    }


# ---------------------------------------------------------------------------
def build_mine(seed: SessionSeed, fp: dict, pem: str, *,
               rounds: Sequence[Sequence[int]] | None = None,
               answers: Sequence[int] | None = None,
               ua: str = UA_DEFAULT, site: Optional[str] = None,
               tguess_plain: str = '{"sc":[376,345],"st":1}',
               requested_id_plain: str = '{"sc":[376,345]}',
               style_theme: str = "default", capi_mode: str = "lightbox",
               lang: str = "zh", render_type: str = "canvas",
               api_breaker: str = "1.6.0", analytics_tier: str = "40",
               tls: Optional[dict] = None,
               resp_gt2: Optional[dict] = None,
               resp_gfct: Optional[dict] = None,
               surl: str = DEFAULT_SURL) -> dict:
    """产出 simple 格式的 mine.json（gt2 + gfct + 每轮 ca）。"""
    site = site or seed.site
    per_round = list(rounds) if rounds else ([list(answers)] if answers else [[0]])
    reqs: List[dict] = [
        build_gt2(fp, pem, public_key=seed.public_key, site=site, ua=ua,
                  style_theme=style_theme, capi_mode=capi_mode,
                  blob=seed.blob if seed.blob is not None else None, surl=surl),
        build_gfct(seed, ua, lang=lang, render_type=render_type,
                   api_breaker=api_breaker, analytics_tier=analytics_tier, surl=surl),
    ]
    for i, ans in enumerate(per_round):
        reqs.append(build_ca(
            seed, ans, tguess_plain=tguess_plain,
            requested_id_plain=requested_id_plain, ua=ua,
            render_type=render_type, analytics_tier=analytics_tier, surl=surl))
    if tls:
        reqs[0]["tls"] = tls
    if resp_gt2:
        reqs[0] = {**reqs[0], "resp_json": resp_gt2}
    if resp_gfct:
        reqs[1] = {**reqs[1], "resp_json": resp_gfct}

    fp_plain = {k: v for k, v in reseal(fp).items() if k != "c"}
    return {
        "meta": {"generator": "arp.generate", "public_key": seed.public_key,
                 "rounds": len(per_round)},
        "session_token": seed.token_base,
        "fp": fp_plain,
        "requests": reqs,
    }


def write(path: str | Path, obj: dict) -> None:
    Path(path).write_text(json.dumps(obj, ensure_ascii=False, indent=2),
                          encoding="utf-8")
