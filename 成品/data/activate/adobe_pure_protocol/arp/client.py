"""纯协议 `mine` 运行器：真的把 gt2 / gfct / ca 发出去。

依赖 curl_cffi（Windows 侧 0.13.0 可用）。requests + provider 组合出票，
并把全过程录成 simple 格式（可直接喂 arp compare）。

    cli = ArkoseClient(public_key, site)
    obj = cli.run(fp, pem, provider=FixedAnswers([[0,2]]))
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from . import generate as gen
from .generate import SessionSeed, UA_DEFAULT, DEFAULT_SURL


@dataclass
class ClientResult:
    obj: dict
    seed: SessionSeed
    rounds: List[dict] = field(default_factory=list)
    solved: bool = False
    denied: bool = False


class ArkoseClient:
    def __init__(self, public_key: str, site: str, *, ua: str = UA_DEFAULT,
                 impersonate: str = "chrome", proxy: Optional[str] = None,
                 timeout: int = 30, surl: str = DEFAULT_SURL):
        self.public_key = public_key
        self.site = site
        self.ua = ua
        self.surl = surl
        self.impersonate = impersonate
        self.proxy = proxy
        self.timeout = timeout

    # ---- 底层 ----
    def _session(self):
        from curl_cffi import requests as creq
        s = creq.Session(impersonate=self.impersonate)
        if self.proxy:
            s.proxies = {"http": self.proxy, "https": self.proxy}
        return s

    @staticmethod
    def _resp_json(r) -> Optional[dict]:
        try:
            return r.json()
        except Exception:
            try:
                return json.loads(r.text)
            except Exception:
                return None

    def _post(self, sess, url: str, headers: dict, body: dict) -> dict:
        r = sess.post(url, headers=headers, data=body, timeout=self.timeout)
        return {
            "url": url, "headers": dict(headers), "body": dict(body),
            "status": r.status_code, "resp_json": self._resp_json(r),
            "resp_text": r.text,
        }

    # ---- 三步 ----
    def gt2(self, sess, fp: dict, pem: str, **kw) -> SessionSeed:
        req = gen.build_gt2(fp, pem, public_key=self.public_key,
                            site=self.site, ua=self.ua, surl=self.surl, **kw)
        out = self._post(sess, req["url"], req["headers"], req["body"])
        resp = out["resp_json"] or {}
        seed = gen.session_from_gt2(self.public_key, self.site, resp)
        seed.resp_gt2 = resp
        self._last_gt2 = {**req, "resp_json": resp, "resp_status": out["status"]}
        if str(resp.get("error", "")).upper() == "DENIED ACCESS":
            raise PermissionError("gt2 被 DENIED ACCESS —— 指纹/请求指纹不过")
        return seed

    def gfct(self, sess, seed: SessionSeed, **kw) -> dict:
        req = gen.build_gfct(seed, self.ua, surl=self.surl, **kw)
        out = self._post(sess, req["url"], req["headers"], req["body"])
        resp = out["resp_json"] or {}
        gen.apply_gfct(seed, resp)
        self._last_gfct = {**req, "resp_json": resp, "resp_status": out["status"]}
        if str(resp.get("error", "")).upper() == "DENIED ACCESS":
            raise PermissionError("gfct 被 DENIED ACCESS")
        return resp

    def ca(self, sess, seed: SessionSeed, answers, *, tguess_plain: str,
           requested_id_plain: str = '{"sc":[376,345]}', **kw) -> dict:
        req = gen.build_ca(seed, answers, tguess_plain=tguess_plain,
                           requested_id_plain=requested_id_plain, ua=self.ua,
                           surl=self.surl, **kw)
        out = self._post(sess, req["url"], req["headers"], req["body"])
        return {**req, "resp_json": out["resp_json"], "resp_status": out["status"]}

    # ---- 全流程 ----
    def run(self, fp: dict, pem: str, provider, *,
            tguess_plain: str = '{"sc":[376,345],"st":1}',
            requested_id_plain: str = '{"sc":[376,345]}',
            max_rounds: int = 12, **kw) -> ClientResult:
        sess = self._session()
        seed = self.gt2(sess, fp, pem, **kw)
        challenge = self.gfct(sess, seed, **kw)
        ca_rounds: List[dict] = []
        solved = False
        denied = False
        for i in range(max_rounds):
            ans = provider.answers_for(i, challenge)
            ex = self.ca(sess, seed, ans, tguess_plain=tguess_plain,
                         requested_id_plain=requested_id_plain, **kw)
            ca_rounds.append(ex)
            resp = ex.get("resp_json") or {}
            if str(resp.get("error", "")).upper() == "DENIED ACCESS":
                denied = True
                break
            if resp.get("response") == "answered":
                solved = bool(resp.get("solved"))
                break
            challenge = resp or challenge

        obj = {
            "meta": {"generator": "arp.client", "public_key": self.public_key,
                     "site": self.site, "rounds": len(ca_rounds),
                     "solved": solved, "denied": denied},
            "session_token": seed.token_base,
            "fp": {k: v for k, v in gen.reseal(fp).items() if k != "c"},
            "requests": [self._last_gt2, self._last_gfct] + ca_rounds,
        }
        return ClientResult(obj=obj, seed=seed, rounds=ca_rounds,
                            solved=solved, denied=denied)
