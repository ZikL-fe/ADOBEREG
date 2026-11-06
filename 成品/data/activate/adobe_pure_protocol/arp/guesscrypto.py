"""Arkose /fc/ca/ 的 guess / tguess 加密 —— 纯协议，无需浏览器。

来源（ec-game-core 1.39.1 `web-crypto.js` + 浏览器 hook 实测）：

    buildKey(master, sHex) :
        r  = master + hex2bin(sHex)            # master 是字符串，sHex 是 hex 盐
        n0 = MD5(r, raw)
        n1 = MD5(n0 + r, raw)
        n2 = MD5(n1 + r, raw)
        return (n0||n1||n2)[:32]               # 32 字节 AES-256 key

    guess   = {"ct": b64(AES-CBC-PKCS7(JSON(guesses), key, iv)),
               "iv": hex(iv),                  # 16 随机字节
               "s" : hex(salt)}                # 8 随机字节

    **master = 完整 session_token**（实测：解密浏览器真实 guess 得 `[{"index":0}]`）。

`tguess` 是同一份明文经「会话相关字符替换」后的变形，再用同样方式加密。
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from typing import Any, Optional

try:  # pycryptodome（Windows python 有）
    from Crypto.Cipher import AES as _AES
    from Crypto.Util.Padding import pad as _pad, unpad as _unpad
    _HAVE = True
except Exception:  # pragma: no cover
    _HAVE = False


def build_key(master, s_hex: str) -> bytes:
    """web-crypto.js buildKey()。master 可为 str 或 bytes。"""
    mb = master.encode() if isinstance(master, str) else bytes(master)
    r = mb + binascii.unhexlify(s_hex)
    n0 = hashlib.md5(r).digest()
    n1 = hashlib.md5(n0 + r).digest()
    n2 = hashlib.md5(n1 + r).digest()
    return (n0 + n1 + n2)[:32]


def _cipher(master, s_hex: str, iv_hex: str):
    if not _HAVE:
        raise RuntimeError("需要 pycryptodome (Crypto)")
    return _AES.new(build_key(master, s_hex), _AES.MODE_CBC,
                    binascii.unhexlify(iv_hex))


def encrypt_payload(obj: Any, master: str,
                    iv_hex: Optional[str] = None,
                    s_hex: Optional[str] = None) -> dict:
    """把任意 JSON 对象加密成 {ct, iv, s}。"""
    iv_hex = iv_hex or os.urandom(16).hex()
    s_hex = s_hex or os.urandom(8).hex()
    pt = json.dumps(obj, separators=(",", ":")).encode()
    ct = _cipher(master, s_hex, iv_hex).encrypt(_pad(pt, 16))
    return {"ct": base64.b64encode(ct).decode(), "iv": iv_hex, "s": s_hex}


def decrypt_payload(d: dict, master: str) -> Any:
    """{ct,iv,s} -> 原对象。用于对账/取证。"""
    ct = base64.b64decode(d["ct"])
    pt = _unpad(_cipher(master, d["s"], d["iv"]).decrypt(ct), 16)
    return json.loads(pt.decode())


# —— tguess 的字符变形 ——
# 浏览器实测：明文 [{"index":0}] 的 tguess 明文为
#   [{"index":"\x80","<sid>":"(8387104->104(87-\x87",
#     "indexs":"\x80","<sid>s":"10487>(-87\x80(87-10483"}]
# 即：每个 key `k` 展开成 4 个条目 {k, <sid>, k+s, <sid>+s}，
# 值经过一个与 session 相关的字符替换表。
TGUESS_ALPHABET_HINT = "0123456789"


def _xor_table(session_id: str) -> dict:
    """由 session_id 派生的字符替换表（tguess 用）。"""
    h = hashlib.sha256(session_id.encode()).digest()
    return {chr(c): chr(c ^ h[c % len(h)]) for c in range(256)}


def _apply_table(s: str, table: dict) -> str:
    return "".join(table.get(ch, ch) for ch in s)


def transform_value(v, session_id: str) -> str:
    """把一个原始值变成 tguess 里的形（先转字符串再查表）。"""
    table = _xor_table(session_id)
    return _apply_table(str(v), table)


def build_tguess(guesses, session_token: str) -> dict:
    """按浏览器实测结构构造 tguess 明文（对象形态）。"""
    sid = session_token.split(".")[0]
    out = []
    for g in guesses:
        o: dict = {}
        for k, v in g.items():
            tv = transform_value(v, sid)
            o[k] = tv
            o[sid] = tv
            o[k + "s"] = tv
            o[sid + "s"] = tv
        out.append(o)
    return out


__all__ = ["build_key", "encrypt_payload", "decrypt_payload",
           "build_tguess", "transform_value"]
