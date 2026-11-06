"""public_key -> RSA 公钥 的获取与缓存。

文章 §二.1：每个 public_key 对应不同 RSA 公钥，藏在
    https://client-api.arkoselabs.com/v2/{public_key}/api.js
的 `case 21:` 分支里（PEM 文本）。

需要联网（curl_cffi，Windows 侧可用）。已有缓存则直接读。
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

CACHE = Path(__file__).resolve().parent / "keycache"
DEFAULT_SURL = "client-api.arkoselabs.com"
API_JS = "https://{surl}/v2/{pk}/api.js"
_PEM_RX = re.compile(
    r"-----BEGIN PUBLIC KEY-----[\s\S]+?-----END PUBLIC KEY-----")

_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36")


def cache_path(public_key: str) -> Path:
    return CACHE / f"{public_key}.pem"


def extract_pem(js_text: str) -> Optional[str]:
    m = _PEM_RX.search(js_text)
    return m.group(0).replace("\\n", "\n") if m else None


def fetch_api_js(public_key: str, *, surl: str = DEFAULT_SURL,
                 impersonate: str = "chrome", timeout: int = 30) -> str:
    from curl_cffi import requests as creq  # 延迟导入，纯逻辑测试不需要
    r = creq.get(API_JS.format(pk=public_key, surl=surl), impersonate=impersonate,
                 timeout=timeout, headers={"user-agent": _UA})
    r.raise_for_status()
    return r.text


def get_public_key_pem(public_key: str, *, surl: str = DEFAULT_SURL,
                       refresh: bool = False,
                       api_js_text: Optional[str] = None) -> str:
    """返回 PEM。api_js_text 给了就不联网（离线/测试用）。"""
    cp = cache_path(public_key)
    if cp.exists() and not refresh:
        return cp.read_text(encoding="utf-8")
    js = api_js_text if api_js_text is not None else fetch_api_js(public_key, surl=surl)
    pem = extract_pem(js)
    if not pem:
        raise ValueError(f"{public_key}: api.js 里没找到 RSA 公钥 PEM")
    CACHE.mkdir(parents=True, exist_ok=True)
    cp.write_text(pem, encoding="utf-8")
    return pem
