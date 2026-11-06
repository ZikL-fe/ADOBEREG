"""MurmurHash3 x64_128 —— 从 data/adobe_api.js 模块 5194 逐行移植。
注意：JS 用 charCodeAt(i)&255，即每个 UTF-16 code unit 只取低字节。"""
M = (1 << 64) - 1

def _u(x): return x & M

def _mul(a, b):
    return _u(a) * _u(b) & M

def _rotl(x, r):
    x = _u(x); r %= 64
    return _u((x << r) | (x >> (64 - r))) if r else x

def _fmix(k):
    k ^= k >> 33
    k = _mul(k, 0xff51afd7ed558ccd)
    k ^= k >> 33
    k = _mul(k, 0xc4ceb9fe1a85ec53)
    k ^= k >> 33
    return _u(k)

C1 = 0x87c37b91114253d5
C2 = 0x4cf5ad432745937f

def murmur3_x64_128(text, seed=0):
    """返回 32 位十六进制小写字符串（与 JS 一致）。"""
    t = text or ""
    n = len(t) % 16
    s = len(t) - n
    b = t.encode("utf-16-le")
    def byte(i):
        return b[i * 2] & 0xFF          # charCodeAt(i) & 255
    h1 = _u(seed); h2 = _u(seed)
    y = 0
    while y < s:
        k1 = (byte(y)|(byte(y+1)<<8)|(byte(y+2)<<16)|(byte(y+3)<<24)
              |(byte(y+4)<<32)|(byte(y+5)<<40)|(byte(y+6)<<48)|(byte(y+7)<<56))
        k2 = (byte(y+8)|(byte(y+9)<<8)|(byte(y+10)<<16)|(byte(y+11)<<24)
              |(byte(y+12)<<32)|(byte(y+13)<<40)|(byte(y+14)<<48)|(byte(y+15)<<56))
        k1 = _rotl(_mul(k1, C1), 31); k1 = _mul(k1, C2); h1 ^= k1
        h1 = _rotl(h1, 27); h1 = _u(h1 + h2); h1 = _u(_mul(h1, 5) + 0x52dce729)
        k2 = _rotl(_mul(k2, C2), 33); k2 = _mul(k2, C1); h2 ^= k2
        h2 = _rotl(h2, 31); h2 = _u(h2 + h1); h2 = _u(_mul(h2, 5) + 0x38495ab5)
        y += 16
    k1 = 0; k2 = 0
    tail = n
    if tail >= 15: k2 |= byte(y+14) << 48
    if tail >= 14: k2 |= byte(y+13) << 40
    if tail >= 13: k2 |= byte(y+12) << 32
    if tail >= 12: k2 |= byte(y+11) << 24
    if tail >= 11: k2 |= byte(y+10) << 16
    if tail >= 10: k2 |= byte(y+9) << 8
    if tail >= 9:
        k2 |= byte(y+8)
        k2 = _rotl(_mul(k2, C2), 33); k2 = _mul(k2, C1); h2 ^= k2
    if tail >= 8: k1 |= byte(y+7) << 56
    if tail >= 7: k1 |= byte(y+6) << 48
    if tail >= 6: k1 |= byte(y+5) << 40
    if tail >= 5: k1 |= byte(y+4) << 32
    if tail >= 4: k1 |= byte(y+3) << 24
    if tail >= 3: k1 |= byte(y+2) << 16
    if tail >= 2: k1 |= byte(y+1) << 8
    if tail >= 1:
        k1 |= byte(y)
        k1 = _rotl(_mul(k1, C1), 31); k1 = _mul(k1, C2); h1 ^= k1
    h1 ^= len(t); h2 ^= len(t)
    h1 = _u(h1 + h2); h2 = _u(h2 + h1)
    h1 = _fmix(h1); h2 = _fmix(h2)
    h1 = _u(h1 + h2); h2 = _u(h2 + h1)
    # JS: (f[0]>>>0) 在前 = 高 32 位在前
    return "".join("%08x%08x" % ((h >> 32) & 0xFFFFFFFF, h & 0xFFFFFFFF) for h in (h1, h2))

def djb2(t):
    """模块 5194 的第二个导出 s（Java String.hashCode）"""
    e = 0
    for ch in t or "":
        e = ((e << 5) - e + ord(ch))
        e = e & 0xFFFFFFFF
        if e >= 0x80000000: e -= 0x100000000
    return e
