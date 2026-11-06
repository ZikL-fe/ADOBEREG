"""
Arkose / FunCaptcha 协议原语 —— 完全对齐 haloowhite 文章 + 实测。

只依赖 pycryptodome（Windows Python 已有）：
    * 步骤1 `c` 参数     : AES-256-GCM + RSA-OAEP(SHA1) -> b64 拼接
    * 步骤2/3 x-ark-esync-value / x-newrelic-timestamp
    * 步骤3 guess/tguess/bio/x-requested-id : CryptoJS AES-256-CBC
                          （OpenSSL EVP_BytesToKey 派生 key/iv）

明文可解密的前提是拿得到 session token（文章已说明）。
"""
from __future__ import annotations

import base64
import json
import time
from typing import Optional, Tuple

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import MD5
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

# --------------------------------------------------------------------------
# 头部时间戳
# --------------------------------------------------------------------------
ESYNC_ALIGNMENT_MS = 21600  # legacy（旧猜测）
# 真实：api.js `i=Date.now()/1e3; a=Math.round(i - i%O.Jy)`，O.Jy=3600 → 当前整点(秒)
ESYNC_ALIGNMENT_SEC = 3600


def arkose_esync_timestamp(ms: Optional[int] = None) -> int:
    """x-ark-esync-value = `Math.round(t - t % 3600)`，t = unix 秒 ⇒ 当前整点边界。

    实测吻合：真机 gt2 `1791892800`(=3600×497748)、iframe `1791957600`(=3600×497766)。
    旧实现错在把它当毫秒且对齐到 21600ms。
    """
    sec = (ms if ms is not None else int(time.time() * 1000)) // 1000
    return round(sec - sec % ESYNC_ALIGNMENT_SEC)


def newrelic_timestamp(ms: Optional[int] = None) -> str:
    """x-newrelic-timestamp：13 位毫秒串 -> 前7位 + "00" + 后6位。"""
    ts = str(ms if ms is not None else int(time.time() * 1000))
    if len(ts) != 13:
        ts = ts.zfill(13)
    return f"{ts[:7]}00{ts[7:13]}"


# --------------------------------------------------------------------------
# 步骤1：`c` 参数 (设备指纹)
# --------------------------------------------------------------------------
def arkose_encrypt_fp(fp_data, public_key_pem: str, *, ensure_ascii: bool = False,
                      oaep_hash: str = "SHA256") -> str:
    """复现 api.js case 21 -> Cn(r, Fo, Do.publicKey, si)。

    返回 base64(iv) + base64(tag) + base64(rsa(aes_key)) + base64(ciphertext)

    ★ 两个关键点（少一个服务端就解不开，指纹等于没交，一律回默认题型 hoople）：
      1. RSA-OAEP 必须用 **SHA-256**（WebCrypto 必须显式指定；PyCryptodome 默认是 SHA-1）
      2. `ensure_ascii=False`：明文含 U+2062 / U+2063 等不可见字符，JS 保留原字符（UTF-8 3B），
         Python 默认会转义成 \\u2062（6B）
    实测：SHA256 -> 与浏览器原文 c 得到完全相同的题型（diceico）；SHA1/384/512 -> hoople。
    """
    if isinstance(fp_data, (dict, list)):
        plaintext = json.dumps(fp_data, separators=(",", ":"),
                               ensure_ascii=ensure_ascii).encode("utf-8")
    elif isinstance(fp_data, str):
        plaintext = fp_data.encode("utf-8")
    else:
        plaintext = bytes(fp_data)

    aes_key = get_random_bytes(32)
    iv = get_random_bytes(12)

    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    rsa_key = RSA.import_key(public_key_pem)
    from Crypto.Hash import SHA1, SHA256, SHA384, SHA512
    _H = {"SHA1": SHA1, "SHA256": SHA256, "SHA384": SHA384, "SHA512": SHA512}
    encrypted_key = PKCS1_OAEP.new(rsa_key, hashAlgo=_H.get(oaep_hash.upper(), SHA256)).encrypt(aes_key)

    return "".join(
        base64.b64encode(x).decode()
        for x in (iv, tag, encrypted_key, ciphertext)
    )


def arkose_decrypt_fp(c: str, private_key_pem: str) -> dict:
    """只有持有该 public_key 对应私钥时可用（研究/自签测试用）。"""
    key = RSA.import_key(private_key_pem)
    ksz = key.size_in_bytes()
    iv_b64_len = 16          # 12 bytes
    tag_b64_len = 24         # 16 bytes
    key_b64_len = 4 * ((ksz + 2) // 3)

    iv = base64.b64decode(c[:iv_b64_len])
    tag = base64.b64decode(c[iv_b64_len:iv_b64_len + tag_b64_len])
    enc_key = base64.b64decode(
        c[iv_b64_len + tag_b64_len: iv_b64_len + tag_b64_len + key_b64_len]
    )
    ct = base64.b64decode(c[iv_b64_len + tag_b64_len + key_b64_len:])

    aes_key = PKCS1_OAEP.new(key).decrypt(enc_key)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
    plain = cipher.decrypt_and_verify(ct, tag)
    try:
        return json.loads(plain)
    except Exception:
        return {"_raw": plain.decode("utf-8", "replace")}


def split_arkose_c(c: str, rsa_bits: int = 2048) -> dict:
    """不持私钥时也能做的结构切片（用于来源间长度/形状对比）。

    两种形态：
      * 新版 CryptoJS 信封 : base64({"ct","iv","s"})
      * 旧版拼接           : base64(iv)+base64(tag)+base64(rsa_key)+base64(ct)
    """
    try:
        obj = json.loads(base64.b64decode(c).decode("utf-8"))
        if isinstance(obj, dict) and {"ct", "iv", "s"} <= set(obj):
            ct = base64.b64decode(obj["ct"])
            return {
                "format": "cryptojs", "ct_len": len(ct),
                "iv_hex_len": len(obj["iv"]), "salt_hex_len": len(obj["s"]),
                "iv": obj["iv"], "s": obj["s"], "total_len": len(c),
            }
    except Exception:
        pass
    ksz = rsa_bits // 8
    key_b64_len = 4 * ((ksz + 2) // 3)
    return {
        "format": "concat",
        "iv_b64": c[:16],
        "tag_b64": c[16:40],
        "rsa_key_b64": c[40:40 + key_b64_len],
        "ct_b64": c[40 + key_b64_len:],
        "ct_len": len(c) - (40 + key_b64_len),
        "total_len": len(c),
    }


# --------------------------------------------------------------------------
# 步骤2/3：CryptoJS AES-256-CBC (EVP_BytesToKey)
# --------------------------------------------------------------------------
def evp_bytes_to_key(token: str, salt: bytes,
                     key_len: int = 32, iv_len: int = 16) -> Tuple[bytes, bytes]:
    """OpenSSL/CryptoJS 兼容的 EVP_BytesToKey（MD5 迭代）。"""
    m = []
    i = 0
    while len(b"".join(m)) < (key_len + iv_len):
        md5 = MD5.new()
        data = token.encode() + salt
        if i > 0:
            data = m[i - 1] + data
        md5.update(data)
        m.append(md5.digest())
        i += 1
    ms = b"".join(m)
    return ms[:key_len], ms[key_len:key_len + iv_len]


def cryptojs_encrypt(plaintext: str, token: str) -> str:
    salt = get_random_bytes(8)
    key, iv = evp_bytes_to_key(token, salt)
    pad_len = 16 - len(plaintext) % 16
    padded = plaintext.encode() + bytes([pad_len] * pad_len)
    ct = AES.new(key, AES.MODE_CBC, iv).encrypt(padded)
    return json.dumps({
        "ct": base64.b64encode(ct).decode(),
        "iv": iv.hex(),
        "s": salt.hex(),
    })


def cryptojs_decrypt(encrypted_json: str, token: str, *, strict: bool = False) -> str:
    data = json.loads(encrypted_json)
    ct = base64.b64decode(data["ct"])
    iv = bytes.fromhex(data["iv"])
    salt = bytes.fromhex(data["s"])
    key, _ = evp_bytes_to_key(token, salt)
    plain = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
    pad = plain[-1]
    if strict and (pad < 1 or pad > 16 or plain[-pad:] != bytes([pad]) * pad):
        raise ValueError("bad PKCS7 padding (wrong password)")
    return plain[:-pad].decode("utf-8", "replace")


def cryptojs_probe(encrypted_json: str) -> dict:
    """不需要 token 也能看出的形状信息。"""
    try:
        d = json.loads(encrypted_json)
    except Exception:
        return {"is_cryptojs": False}
    if not isinstance(d, dict):
        return {"is_cryptojs": False}
    ks = set(d.keys())
    try:
        ct_len = len(base64.b64decode(d.get("ct", "")))
    except Exception:
        ct_len = (len(d.get("ct", "")) * 3) // 4
    shape = {
        "is_cryptojs": {"ct", "iv", "s"} <= ks,
        "ct_b64_len": len(d.get("ct", "")),
        "iv_hex_len": len(d.get("iv", "")),
        "salt_hex_len": len(d.get("s", "")),
        "ct_len": ct_len,
        "ct_pad16_ok": ct_len % 16 == 0,
    }
    return shape


# x-requested-id 用的密钥是 REQUESTED{token}ID
def requested_id_key(session_token: str) -> str:
    return f"REQUESTED{session_token}ID"
