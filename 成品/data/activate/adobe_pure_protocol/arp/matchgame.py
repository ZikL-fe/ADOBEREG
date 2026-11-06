"""capi 4.6.0 图片题（match-game）纯协议运行器。

链路（与 arks-client.adobe.com 实测一致）：
    GET  /v2/<pk>/settings
    POST /fc/gt2/public_key/<pk>      指纹 -> session token + sid
    POST /fc/gfct/                    取题 -> {session_token, challengeID, game_data}
    POST /fc/ekey/                    仅 encrypted_mode=1 时需要（AES-CBC 密钥）
    POST /fc/ca/                      提交答案（form-urlencoded）
    POST /fc/a/                       埋点

提交包构造见 arp.challenge。全部走 curl_cffi（Chrome TLS）。
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence
from urllib.parse import urlencode

from . import challenge as C
from . import generate as gen
from .generate import UA_DEFAULT, DEFAULT_SURL

FORM_CT = "application/x-www-form-urlencoded; charset=UTF-8"


def _sid_from_token(token: str, default: str = "us-west-2") -> str:
    for part in str(token).split("|"):
        if part.startswith("r="):
            return part[2:] or default
    return default


@dataclass
class GameState:
    token: str = ""
    sid: str = "us-west-2"
    pow: bool = False
    challenge_id: str = ""
    game_token: str = ""
    game_data: Dict = field(default_factory=dict)
    challenge_url: str = ""
    dapib_url: str = ""
    dapib_src: str = ""
    decryption_key: Optional[str] = None
    rounds: List[dict] = field(default_factory=list)

    @property
    def session_token(self) -> str:
        return self.token.split("|", 1)[0]

    @property
    def images(self) -> List[str]:
        gd = self.game_data or {}
        return (gd.get("_challenge_imgs") or gd.get("challengeImages") or [])


class MatchGame:
    def __init__(self, public_key: str, site: str, *,
                 surl: str = DEFAULT_SURL, ua: str = UA_DEFAULT,
                 proxy: Optional[str] = None, timeout: int = 30,
                 impersonate: Optional[str] = None, blob: Optional[str] = None,
                 capi_mode: str = "inline",
                 fp_override: Optional[str] = None,
                 node: Optional[str] = None,
                 accept_language: str = "en-US,en;q=0.9",
                 identity=None):
        self.public_key = public_key
        self.site = site
        self.surl = surl
        self.ua = ua
        self.identity = identity
        self.accept_language = getattr(identity, "accept_language", None) or accept_language
        self.impersonate = impersonate or "chrome"
        if identity is not None:
            self.ua = getattr(identity, "ua", ua) or ua
            if not impersonate:
                self.impersonate = getattr(identity, "impersonate", None) or self.impersonate
            self.blob = blob
        self.blob = blob
        self.capi_mode = capi_mode
        self.fp_override = fp_override
        self.proxy = proxy
        self.timeout = timeout
        self.node = node
        self.log: List[dict] = []

    # ---- 底层 ----
    def session(self):
        from curl_cffi import requests as creq
        from .identity import curl_proxy
        s = creq.Session(impersonate=self.impersonate)
        px = curl_proxy(self.proxy)
        if px:
            s.proxies = {"http": px, "https": px}
        return s

    def _base(self) -> str:
        return f"https://{self.surl}"

    def _fc_headers(self, ms: int, xri: Optional[str] = None,
                    referer: Optional[str] = None) -> Dict[str, str]:
        ts = str(ms)
        h = {
            "content-type": FORM_CT,
            "accept": "*/*",
            "cache-control": "no-cache",
            "x-requested-with": "XMLHttpRequest",
            "x-newrelic-timestamp": ts,
            "user-agent": self.ua,
            "accept-language": self.accept_language,
            "cookie": f"timestamp={ts}",
        }
        if referer:
            h["referer"] = referer
        if xri:
            h["x-requested-id"] = xri
        return h

    def game_core_referer(self, st: "GameState") -> str:
        """游戏帧的 referer —— 浏览器带上它证明"当前在跑哪个 challenge"。"""
        from urllib.parse import quote
        cdn = f"{self._base()}/cdn/fc"
        p = (f"session={st.session_token}&r={st.sid}&meta=3&meta_width=400"
             f"&meta_height=303&metabgclr=transparent&metaiconclr=%23555555"
             f"&guitextcolor=%23000000&pk={self.public_key}&at=40&ag=101"
             f"&cdn_url={quote(cdn, safe='')}&surl={quote(self.surl, safe='')}")
        return (f"{self._base()}/fc/assets/ec-game-core/game-core/1.39.1"
                f"/standard/index.html?{p}")

    @staticmethod
    def x_requested_id(session_token: str, sc=(200, 233)) -> str:
        """`X-Requested-ID` 头 —— secretTransportedHeader（提交坐标）。

        源码（lib.chunk `callECApi`）：
            C['X-Requested-ID'] = encryptECData(JSON.stringify(b),
                                                'REQUESTED'.concat(sessionToken, 'ID'))
        实测明文：{"sc":[199,233]}（提交点击在游戏 iframe 内的坐标）。
        加密方案与 guess 相同（buildKey + AES-CBC）。
        """
        from . import guesscrypto as G
        master = "REQUESTED" + session_token + "ID"
        return json.dumps(G.encrypt_payload({"sc": list(sc)}, master),
                          separators=(",", ":"))

    def _post(self, sess, path: str, fields: Dict, *, ms: Optional[int] = None):
        import time
        ms = ms or int(time.time() * 1000)
        url = self._base() + path
        body = urlencode({k: v for k, v in fields.items() if v not in (None, "")})
        r = sess.post(url, headers=self._fc_headers(ms), data=body,
                      timeout=self.timeout)
        entry = {"stage": path.strip("/").replace("/", "_"), "url": url,
                 "body": body, "status": r.status_code}
        try:
            entry["resp_json"] = r.json()
        except Exception:
            entry["resp_json"] = None
            entry["resp_text"] = r.text[:400]
        self.log.append(entry)
        return entry

    def _get(self, sess, path: str):
        r = sess.get(self._base() + path, timeout=self.timeout,
                     headers={"user-agent": self.ua, "accept": "*/*"})
        entry = {"stage": path.strip("/"), "url": self._base() + path,
                 "status": r.status_code}
        try:
            entry["resp_json"] = r.json()
        except Exception:
            entry["resp_json"] = None
        self.log.append(entry)
        return entry

    def _post_json(self, sess, path: str, body: dict):
        import time
        ms = int(time.time() * 1000)
        url = self._base() + path
        h = {"content-type": "application/json",
             "x-requested-with": "XMLHttpRequest",
             "x-newrelic-timestamp": str(ms),
             "cookie": f"timestamp={ms}", "user-agent": self.ua,
             "referer": "https://auth.services.adobe.com/"}
        r = sess.post(url, headers=h, data=json.dumps(body), timeout=self.timeout)
        try:
            resp = r.json()
        except Exception:
            resp = {"error": "bad json", "_text": r.text[:200]}
        e = {"stage": path.strip("/").replace("/", "_"), "url": url,
             "body": body, "status": r.status_code, "resp_json": resp}
        self.log.append(e)
        return e

    def pows(self, sess, st: "GameState", *, max_rounds: int = 6,
             span: int = 300_000_000, parallel: bool = True,
             setup: Optional[dict] = None) -> bool:
        """完成 PoW（纯 Python 复现 worker）：setup -> started -> 计算 -> check。

        返回 True 表示服务端给了 action=challenge（可以取图片题）。
        若返回 action=block，说明出口 IP 被风控（PoW 不可解）。
        """
        from . import pow as powmod
        if setup is None:
            e = self._get(sess, f"/pows/setup?session_token={st.session_token}")
            setup = e.get("resp_json") or {}
        if not setup:
            return False
        setup["session_token"] = st.session_token
        if "pow_token" not in setup:
            # 有些场景 gt2 已带 pow_token；没有就重新拉一次 setup
            e2 = self._get(sess, f"/pows/setup?session_token={st.session_token}")
            s2 = e2.get("resp_json") or {}
            if s2.get("pow_token"):
                setup = {**setup, **s2, "session_token": st.session_token}
            else:
                return False
        import time
        for rnd in range(max_rounds):
            self._post_json(sess, "/pows/started", {
                "session_token": st.session_token, "pow_token": setup["pow_token"],
                "round": rnd, "time": int(time.time() * 1000)})
            try:
                comp = powmod.run_pow_node(setup, proxy=self.proxy)
            except TimeoutError:
                return False
            out = self._post_json(sess, "/pows/check",
                                  powmod.check_payload(setup, comp, st.session_token))
            resp = out.get("resp_json") or {}
            if resp.get("action") == "challenge":
                return True
            if resp.get("action") != "next":
                return False
            seq = setup.get("sequence")
            setup = {**resp, "session_token": st.session_token}
            if "sequence" not in setup and seq:
                setup["sequence"] = seq
        return False

    # ---- 步骤 ----
    def settings(self, sess) -> dict:
        return self._get(sess, f"/v2/{self.public_key}/settings").get("resp_json") or {}

    def gt2(self, sess, fp: dict, pem: str) -> GameState:
        req = gen.build_gt2(fp, pem, public_key=self.public_key, site=self.site,
                            ua=self.ua, surl=self.surl, capi_version="4.6.0",
                            blob=self.blob, capi_mode=self.capi_mode,
                            fingerprint_override=self.fp_override,
                            accept_language=self.accept_language)
        r = sess.post(req["url"], headers=req["headers"], data=req["body"],
                      timeout=self.timeout)
        try:
            resp = r.json()
        except Exception:
            resp = {}
        self.log.append({"stage": "gt2", "url": req["url"], "body": req["body"],
                         "status": r.status_code, "resp_json": resp})
        if str(resp.get("error", "")).upper().startswith("DENIED"):
            raise PermissionError("gt2 DENIED ACCESS")
        tok = str(resp.get("token", ""))
        st = GameState(token=tok, sid=_sid_from_token(tok))
        st.pow = bool(resp.get("pow"))
        return st

    def gfct(self, sess, st: GameState) -> dict:
        e = self._post(sess, "/fc/gfct/", {
            "token": st.session_token, "sid": st.sid, "render_type": "canvas",
            "lang": "en", "isAudioGame": "false",
            "is_compatibility_mode": "false", "apiBreakerVersion": "green",
            "analytics_tier": "40"})
        resp = e.get("resp_json") or {}
        st.game_token = str(resp.get("game_token", "") or resp.get("gameToken", ""))
        st.challenge_id = str(resp.get("challengeID", "") or resp.get("challenge_id", ""))
        st.challenge_url = str(resp.get("challengeURL", ""))
        st.dapib_url = str(resp.get("dapib_url", ""))
        st.game_data = resp.get("game_data") or {}
        return resp

    def dapib(self, sess, st: GameState) -> str:
        """下载本 session 的 dapib 脚本（算 tguess 用；每 session 多态）。"""
        if st.dapib_src:
            return st.dapib_src
        if not st.dapib_url:
            raise RuntimeError("gfct 未返回 dapib_url")
        r = sess.get(st.dapib_url, timeout=self.timeout)
        st.dapib_src = r.text
        return st.dapib_src

    def tguess_for(self, st: GameState, guesses) -> list:
        """用**真 dapib 脚本**算出 tguess 明文（见 arp/dapib.py）。"""
        from . import dapib as D
        if not st.dapib_src:
            raise RuntimeError("先调用 self.dapib(sess, st)")
        if guesses and isinstance(guesses[0], int):
            guesses = [{"index": n} for n in guesses]
        node = self.node or D.find_node()
        return D.run_dapib(st.dapib_src, D.build_answer(guesses, st.session_token),
                           node=node)

    def ekey(self, sess, st: GameState) -> dict:
        e = self._post(sess, "/fc/ekey/", {
            "session_token": st.session_token, "analytics_tier": "40"})
        resp = e.get("resp_json") or {}
        st.decryption_key = resp.get("decryption_key")
        return resp

    def ca(self, sess, st: GameState, response, *, bio: Optional[str] = None,
           ecdata: Optional[str] = None, height: int = 400, width: int = 400,
           r: str = "", lang: str = "en", encrypted: bool = True,
           game_token: Optional[str] = None, tguess=None,
           sc: Optional[tuple] = (200, 233)) -> dict:
        """POST /fc/ca/ 提交答案。

        encrypted=True（默认，**2026 实测通过格式**）：
            guess = encryptECData(JSON(guesses), session_token)，且必须带 game_token。
            → HTTP 200（以前发明文 response= 会 DENIED ACCESS）。
        encrypted=False：早期的明文 `response=` 版本，仅用于历史对账。
        """
        if encrypted:
            body = C.build_ca_body_encrypted(
                session_token=st.session_token,
                game_token=game_token or st.challenge_id,
                guesses=response, sid=st.sid or "us-east-1", analytics_tier=40,
                bio=bio, ecdata=ecdata, height=height, width=width,
                tguess=tguess)
        else:
            body = C.build_ca_body(
                session_token=st.session_token,
                response=response, language=lang, r=r or st.session_token[-4:],
                analytics_tier=40, bio=bio, ecdata=ecdata, height=height, width=width)
        import time
        ms = int(time.time() * 1000)
        url = self._base() + "/fc/ca/"
        xri = self.x_requested_id(st.session_token, sc) if sc else None
        rr = sess.post(url, headers=self._fc_headers(ms, xri,
                                                     self.game_core_referer(st)),
                       data=body, timeout=self.timeout)
        try:
            resp = rr.json()
        except Exception:
            resp = {"_text": rr.text[:300]}
        e = {"stage": "ca", "url": url, "body": body, "status": rr.status_code,
             "resp_json": resp}
        self.log.append(e)
        st.rounds.append(e)
        return e

    def analytics(self, sess, st: GameState, category: str, action: str) -> dict:
        return self._post(sess, "/fc/a/", {
            "sid": st.sid, "session_token": st.session_token,
            "analytics_tier": "40", "disableCookies": "false",
            "game_token": st.challenge_id or st.game_token,
            "game_type": str((st.game_data or {}).get("gameType", 4)),
            "render_type": "canvas", "is_compatibility_mode": "false",
            "category": category, "action": action})

    # ---- 全流程 ----
    def run(self, fp: dict, pem: str, provider=None, *,
            response=None, max_rounds: int = 8, do_ekey: bool = False,
            random_response: bool = False) -> dict:
        """provider: answers_for(round_i, game_state) -> 下标序列。
        random_response: 忽略 provider，随机填 response（验证“只校验信封”假设）。"""
        import random
        import time
        sess = self.session()
        st = self.gt2(sess, fp, pem)
        self.settings(sess)
        self.gfct(sess, st)
        if do_ekey:
            self.ekey(sess, st)
        solved = answered = denied = False
        for i in range(max_rounds):
            if random_response:
                ans = [random.randint(0, 5)]
            elif response is not None:
                ans = response
            elif provider is not None:
                ans = provider.answers_for(i, st.game_data)
            else:
                ans = [0]
            ex = self.ca(sess, st, ans, r=f"{int(time.time())%10000}")
            resp = ex.get("resp_json") or {}
            if str(resp.get("error", "")).upper().startswith("DENIED"):
                denied = True
                break
            answered = bool(resp.get("answered") or resp.get("response") == "answered")
            if answered:
                solved = bool(resp.get("solved"))
                break
            if resp.get("challengeImages"):
                st.game_data = {**(st.game_data or {}), **resp}
            if resp.get("challengeID"):
                st.challenge_id = str(resp["challengeID"])
        return {"state": st, "rounds": st.rounds, "solved": solved,
                "answered": answered, "denied": denied,
                "last": (st.rounds[-1]["resp_json"] if st.rounds else None)}
