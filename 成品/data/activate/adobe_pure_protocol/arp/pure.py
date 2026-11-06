"""纯协议出票：封装 buggerlogger/arkose-solver。

它自动从 api.js 派生站点 RSA 公钥、合成真机 BDA 指纹、AES-GCM+RSA-OAEP 加密，
POST /fc/gt2/public_key/{pk} 拿 **sup=1 的 suppressed token** —— 无浏览器、无打码。

    pip install arkose-solver        # 依赖 cryptography + curl_cffi
    python -m arp solve --surl https://arks-client.adobe.com \
        --pk 430FF2C3-1AB1-40B7-8BE7-44FC683FE02C --site https://auth.services.adobe.com
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional


def available() -> bool:
    try:
        import arkose_solver  # noqa: F401
        return True
    except Exception:
        return False


def solve(*, surl: str, public_key: str, site: Optional[str] = None,
          proxy: Optional[str] = None, user_agent: Optional[str] = None,
          language: str = "en-US", capi_mode: str = "lightbox",
          **kw) -> dict:
    """返回 {token, suppressed, timings}。"""
    from arkose_solver import Solver
    s = Solver(surl=surl, public_key=public_key, site=site, proxy=proxy,
               user_agent=user_agent, language=language, capi_mode=capi_mode, **kw)
    res = s.solve()
    return {"token": res.token, "suppressed": bool(res.suppressed),
            "timings": dict(res.timings or {}), "surl": surl,
            "public_key": public_key, "site": site}


def token_to_capture(token: str, *, surl: str, public_key: str,
                     site: str = "", fp: Optional[dict] = None,
                     path: Optional[str] = None) -> dict:
    """把出票结果包成 simple 格式（可喂 arp compare / 入库）。"""
    obj = {
        "meta": {"generator": "arp.pure", "surl": surl, "site": site,
                 "public_key": public_key,
                 "suppressed": "sup=1" in (token or "")},
        "session_token": (token or "").split("|", 1)[0],
        "fp": fp,
        "requests": [{"stage": "gt2",
                      "url": f"https://{surl.replace('https://', '').strip('/')}"
                             f"/fc/gt2/public_key/{public_key}",
                      "body": {"public_key": public_key, "site": site}}],
        "responses": [{"url": "gt2", "status": 200,
                       "text": json.dumps({"token": token})}],
    }
    if path:
        Path(path).write_text(json.dumps(obj, ensure_ascii=False, indent=2),
                              encoding="utf-8")
    return obj
