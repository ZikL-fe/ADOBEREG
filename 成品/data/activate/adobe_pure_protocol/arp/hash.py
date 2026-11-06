"""MurmurHash3 (x86_128 / x64_128) 与 Arkose 用到的编码工具。

用途：
  * FP 字段 `f` = murmur128(fe.join(";"))  —— 沙箱可重算，用来验指纹自洽
  * FP 字段 `wh` = 两个 murmur128(seed=420) 拼接
  * FP 字段 `n`  = base64(unix_seconds)
"""
from __future__ import annotations

import base64
import struct
import time


def _rotl32(x: int, r: int) -> int:
    x &= 0xFFFFFFFF
    return ((x << r) | (x >> (32 - r))) & 0xFFFFFFFF


def _fmix32(h: int) -> int:
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & 0xFFFFFFFF
    h ^= h >> 16
    return h


def murmur3_x86_128(data: bytes, seed: int = 0) -> str:
    """murmurhash3js 的 x86.hash128（Arkose FP 文档用的就是这个）。"""
    c1, c2, c3, c4 = 0x239B961B, 0xAB0E9789, 0x38B34AE5, 0xA1E38B93
    h1 = h2 = h3 = h4 = seed & 0xFFFFFFFF
    length = len(data)
    nblocks = length // 16
    for i in range(nblocks):
        k1, k2, k3, k4 = struct.unpack_from("<IIII", data, i * 16)
        k1 = (k1 * c1) & 0xFFFFFFFF; k1 = _rotl32(k1, 15); k1 = (k1 * c2) & 0xFFFFFFFF; h1 ^= k1
        h1 = _rotl32(h1, 19); h1 = (h1 + h2) & 0xFFFFFFFF; h1 = (h1 * 5 + 0x561CCD1B) & 0xFFFFFFFF
        k2 = (k2 * c2) & 0xFFFFFFFF; k2 = _rotl32(k2, 16); k2 = (k2 * c3) & 0xFFFFFFFF; h2 ^= k2
        h2 = _rotl32(h2, 17); h2 = (h2 + h3) & 0xFFFFFFFF; h2 = (h2 * 5 + 0x0BCAA747) & 0xFFFFFFFF
        k3 = (k3 * c3) & 0xFFFFFFFF; k3 = _rotl32(k3, 17); k3 = (k3 * c4) & 0xFFFFFFFF; h3 ^= k3
        h3 = _rotl32(h3, 15); h3 = (h3 + h4) & 0xFFFFFFFF; h3 = (h3 * 5 + 0x96CD1C35) & 0xFFFFFFFF
        k4 = (k4 * c4) & 0xFFFFFFFF; k4 = _rotl32(k4, 18); k4 = (k4 * c1) & 0xFFFFFFFF; h4 ^= k4
        h4 = _rotl32(h4, 13); h4 = (h4 + h1) & 0xFFFFFFFF; h4 = (h4 * 5 + 0x32AC3B17) & 0xFFFFFFFF

    tail = data[nblocks * 16:]
    k1 = k2 = k3 = k4 = 0
    tl = len(tail)
    if tl >= 15: k4 ^= tail[14] << 16
    if tl >= 14: k4 ^= tail[13] << 8
    if tl >= 13:
        k4 ^= tail[12]
        k4 = (k4 * c4) & 0xFFFFFFFF; k4 = _rotl32(k4, 18); k4 = (k4 * c1) & 0xFFFFFFFF; h4 ^= k4
    if tl >= 12: k3 ^= tail[11] << 24
    if tl >= 11: k3 ^= tail[10] << 16
    if tl >= 10: k3 ^= tail[9] << 8
    if tl >= 9:
        k3 ^= tail[8]
        k3 = (k3 * c3) & 0xFFFFFFFF; k3 = _rotl32(k3, 17); k3 = (k3 * c4) & 0xFFFFFFFF; h3 ^= k3
    if tl >= 8: k2 ^= tail[7] << 24
    if tl >= 7: k2 ^= tail[6] << 16
    if tl >= 6: k2 ^= tail[5] << 8
    if tl >= 5:
        k2 ^= tail[4]
        k2 = (k2 * c2) & 0xFFFFFFFF; k2 = _rotl32(k2, 16); k2 = (k2 * c3) & 0xFFFFFFFF; h2 ^= k2
    if tl >= 4: k1 ^= tail[3] << 24
    if tl >= 3: k1 ^= tail[2] << 16
    if tl >= 2: k1 ^= tail[1] << 8
    if tl >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF; k1 = _rotl32(k1, 15); k1 = (k1 * c2) & 0xFFFFFFFF; h1 ^= k1

    h1 ^= length; h2 ^= length; h3 ^= length; h4 ^= length
    h1 = (h1 + h2 + h3 + h4) & 0xFFFFFFFF
    h2 = (h2 + h1) & 0xFFFFFFFF; h3 = (h3 + h1) & 0xFFFFFFFF; h4 = (h4 + h1) & 0xFFFFFFFF
    h1 = _fmix32(h1); h2 = _fmix32(h2); h3 = _fmix32(h3); h4 = _fmix32(h4)
    h1 = (h1 + h2 + h3 + h4) & 0xFFFFFFFF
    h2 = (h2 + h1) & 0xFFFFFFFF; h3 = (h3 + h1) & 0xFFFFFFFF; h4 = (h4 + h1) & 0xFFFFFFFF
    return "".join(f"{v:08x}" for v in (h1, h2, h3, h4))


def murmur3_x64_128(data: bytes, seed: int = 0) -> str:
    """x64.hash128（部分实现/后端口径）。"""
    M = 0xFFFFFFFFFFFFFFFF
    c1, c2 = 0x87C37B91114253D5, 0x4CF5AD432745937F
    h1 = h2 = seed & M
    nblocks = len(data) // 16
    for i in range(nblocks):
        k1, k2 = struct.unpack_from("<QQ", data, i * 16)
        k1 = (k1 * c1) & M; k1 = ((k1 << 31) | (k1 >> 33)) & M; k1 = (k1 * c2) & M; h1 ^= k1
        h1 = ((h1 << 27) | (h1 >> 37)) & M; h1 = (h1 + h2) & M; h1 = (h1 * 5 + 0x52DCE729) & M
        k2 = (k2 * c2) & M; k2 = ((k2 << 33) | (k2 >> 31)) & M; k2 = (k2 * c1) & M; h2 ^= k2
        h2 = ((h2 << 31) | (h2 >> 33)) & M; h2 = (h2 + h1) & M; h2 = (h2 * 5 + 0x38495AB5) & M

    tail = data[nblocks * 16:]
    k1 = k2 = 0
    tl = len(tail)
    for i in range(tl - 1, 7, -1):
        k2 ^= tail[i] << ((i - 8) * 8)
    if tl > 8:
        k2 = (k2 * c2) & M; k2 = ((k2 << 33) | (k2 >> 31)) & M; k2 = (k2 * c1) & M; h2 ^= k2
    for i in range(min(tl, 8) - 1, -1, -1):
        k1 ^= tail[i] << (i * 8)
    if tl > 0:
        k1 = (k1 * c1) & M; k1 = ((k1 << 31) | (k1 >> 33)) & M; k1 = (k1 * c2) & M; h1 ^= k1

    h1 ^= len(data); h2 ^= len(data)
    h1 = (h1 + h2) & M; h2 = (h2 + h1) & M
    for h in ("h1", "h2"):
        v = h1 if h == "h1" else h2
        v ^= v >> 33; v = (v * 0xFF51AFD7ED558CCD) & M
        v ^= v >> 33; v = (v * 0xC4CEB9FE1A85EC53) & M
        v ^= v >> 33
        if h == "h1": h1 = v
        else: h2 = v
    h1 = (h1 + h2) & M; h2 = (h2 + h1) & M
    return "".join(f"{v:016x}" for v in (h1, h2))


def fp_fe_digest(fe, kind: str = "x64") -> str:
    """f = murmur3_x64_128( ';'.join(fe 各项冒号后的值), seed=0 )  —— 真 api.js 算法，已双向验证。

    证据：data/fp_pack.json 与 data/fp_real_pack.json 两份真浏览器抓包均逐字节吻合。
    """
    from .murmur3 import murmur3_x64_128 as _m
    items = fe if isinstance(fe, list) else [fe]
    vals = []
    for x in items:
        s = x if isinstance(x, str) else _js_str(x)
        vals.append(s.split(":", 1)[1] if ":" in s else s)
    return _m(";".join(vals), 0)


def ife_digest(fe) -> str:
    """ife_hash = murmur3_x64_128( ', '.join(fe), seed=38 )  —— 已双向验证。"""
    from .murmur3 import murmur3_x64_128 as _m
    items = fe if isinstance(fe, list) else [fe]
    return _m(", ".join(x if isinstance(x, str) else _js_str(x) for x in items), 38)


def wh_digest_real(window_keys, proto_keys=None) -> str:
    """wh = murmur3_x64_128(sorted(own), 420) + '|' + murmur3_x64_128(proto, 420)"""
    from .murmur3 import murmur3_x64_128 as _m
    return _m("|".join(sorted(window_keys)), 420) + "|" + _m("|".join(proto_keys or []), 420)


def _js_str(x) -> str:
    if isinstance(x, bool):
        return "true" if x else "false"
    if isinstance(x, list):
        return ",".join(_js_str(i) for i in x)
    if x is None:
        return "null"
    return str(x)


def wh_digest(window_keys, proto_keys=None, seed: int = 420) -> str:
    """wh = murmur128(sorted(own) seed=420) + '|' + murmur128(proto chain seed=420)。"""
    own = sorted(k for k in window_keys
                 if not k.startswith(("f_", "arkoseLabsClientApi", "webpack")))
    a = murmur3_x86_128("|".join(own).encode(), seed)
    b = murmur3_x86_128("|".join(proto_keys or []).encode(), seed)
    return f"{a}|{b}"


def b64_unix_seconds(sec: int | None = None) -> str:
    sec = int(time.time()) if sec is None else sec
    return base64.b64encode(str(sec).encode()).decode()


def b64_unix_seconds_decode(v: str) -> int:
    return int(base64.b64decode(v).decode())
