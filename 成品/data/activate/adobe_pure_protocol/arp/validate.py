"""单来源自检 = 把"对方要校验的东西"显式化成一组可执行断言。

风控/服务端真正会看的不外乎这几类，任何一条不过都可能吃
{"error":"DENIED ACCESS"} 或进入 POW / 高难度题。
"""
from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from typing import List, Optional

from . import crypto, hash as ahash
from .model import Capture

NR_RX = re.compile(r"^\d{7}00\d{6}$")
UA_HINT = re.compile(r"Chrome/\d+", re.I)


@dataclass
class Finding:
    level: str      # ERROR | WARN | INFO | OK
    code: str
    msg: str

    def __str__(self) -> str:
        return f"[{self.level:5}] {self.code}: {self.msg}"


def validate(cap: Capture) -> List[Finding]:
    f: List[Finding] = []
    gt2, gfct, ca = cap.by_stage("gt2"), cap.by_stage("gfct"), cap.by_stage("ca")

    # ---- 链路完整性 ----
    for st, ex in (("gt2", gt2), ("gfct", gfct), ("ca", ca)):
        if ex is None:
            f.append(Finding("ERROR", "chain.missing", f"缺少 {st} 请求"))
    if any(x is None for x in (gt2, gfct, ca)):
        return f
    extra = [e.stage for e in cap.exchanges if e.stage == "other"]
    if extra:
        f.append(Finding("WARN", "chain.extra", f"存在非标准 Arkose 请求 x{len(extra)}"))

    # ---- UA 一致 ----
    uas = {
        "gt2.body.userbrowser": gt2.body.get("userbrowser", ""),
        "gt2.header.user-agent": gt2.headers.get("user-agent", ""),
        "gfct.header.user-agent": gfct.headers.get("user-agent", ""),
        "ca.header.user-agent": ca.headers.get("user-agent", ""),
    }
    uniq = {v for v in uas.values() if v}
    required = {"gt2.body.userbrowser", "gt2.header.user-agent", "ca.header.user-agent"}
    missing = [k for k, v in uas.items() if not v]
    if missing and required & set(missing):
        f.append(Finding("ERROR", "ua.missing", f"必需 UA 缺失: {missing}"))
    elif missing:
        f.append(Finding("WARN", "ua.missing", f"UA 缺失: {missing}"))
    if len(uniq) > 1:
        f.append(Finding("ERROR", "ua.inconsistent", f"UA 不一致: {uas}"))
    elif uniq and not UA_HINT.search(next(iter(uniq))):
        f.append(Finding("WARN", "ua.odd", "UA 不像真实 Chrome"))
    else:
        f.append(Finding("OK", "ua.consistent", "UA 全链一致"))

    # ---- token / sid / game_token 链 ----
    tok_full = (gt2.resp_json or {}).get("token") if isinstance(gt2.resp_json, dict) else None
    sid = (gt2.resp_json or {}).get("session_id") if isinstance(gt2.resp_json, dict) else None
    if isinstance(tok_full, str) and "|" in tok_full:
        base = tok_full.split("|", 1)[0]
        if gfct.body.get("token") and gfct.body["token"] != base:
            f.append(Finding("ERROR", "token.mismatch",
                             "gfct.token != gt2.token 第一段"))
        if ca.body.get("session_token") and ca.body["session_token"] != base:
            f.append(Finding("ERROR", "token.session_mismatch",
                             "ca.session_token != gt2.token 第一段"))
        if not gfct.body.get("token"):
            f.append(Finding("WARN", "token.absent", "未拿步骤1响应，无法回验 token 链"))
    gtok = (gfct.resp_json or {}).get("game_token") if isinstance(gfct.resp_json, dict) else None
    if gtok and ca.body.get("game_token") and ca.body["game_token"] != gtok:
        f.append(Finding("ERROR", "game_token.mismatch", "ca.game_token != gfct.game_token"))

    # ---- 时间戳格式 ----
    es = gt2.headers.get("x-ark-esync-value")
    if es:
        try:
            v = int(es)
            if v % crypto.ESYNC_ALIGNMENT_MS != 0:
                f.append(Finding("ERROR", "esync.not_aligned",
                                 f"x-ark-esync-value 未按 21600ms 对齐: {v}"))
            else:
                f.append(Finding("OK", "esync.aligned", "x-ark-esync-value 已对齐"))
        except ValueError:
            f.append(Finding("ERROR", "esync.format", f"x-ark-esync-value 非整数: {es}"))
    else:
        f.append(Finding("WARN", "esync.absent", "缺少 x-ark-esync-value"))

    for st, ex in (("gfct", gfct), ("ca", ca)):
        nr = ex.headers.get("x-newrelic-timestamp")
        if nr and not NR_RX.match(nr):
            f.append(Finding("ERROR", "newrelic.format",
                             f"{st} x-newrelic-timestamp 格式异常: {nr}"))

    # ---- 固定字段 ----
    if gt2.body.get("capi_mode") and gt2.body["capi_mode"] not in ("lightbox", "inline"):
        f.append(Finding("WARN", "capi_mode.odd", gt2.body["capi_mode"]))
    if gt2.body.get("data[blob]") in (None, "undefined", ""):
        f.append(Finding("INFO", "blob.absent", "data[blob]=undefined（部分站点正常）"))
    if not gt2.body.get("c"):
        f.append(Finding("ERROR", "c.absent", "步骤1缺少 c 设备指纹"))

    # ---- c 结构 ----
    c = gt2.body.get("c")
    if c:
        sh = crypto.split_arkose_c(c)
        if len(sh["iv_b64"]) != 16 or len(sh["tag_b64"]) != 24:
            f.append(Finding("ERROR", "c.shape", f"c 头部切分异常: {sh}"))
        if len(sh["rsa_key_b64"]) not in (344, 512):
            f.append(Finding("WARN", "c.rsa_len",
                             f"RSA 段长度 {len(sh['rsa_key_b64'])}（2048=>344, 3072=>512）"))

    # ---- 解密 guess/tguess/bio ----
    if cap.session_token:
        for name in ("guess", "tguess", "bio"):
            blob = ca.body.get(name)
            if not blob:
                continue
            try:
                plain = crypto.cryptojs_decrypt(blob, cap.session_token)
            except Exception as ex:
                f.append(Finding("ERROR", f"{name}.undecryptable",
                                 f"{name} 无法用 session token 解密: {type(ex).__name__}"))
                continue
            if name == "guess":
                try:
                    arr = json.loads(plain)
                    if not isinstance(arr, list) or not all("index" in x for x in arr):
                        f.append(Finding("WARN", "guess.shape",
                                         f"guess 明文结构异常: {plain[:80]}"))
                    else:
                        f.append(Finding("OK", "guess.ok",
                                         f"guess 明文可解 index={[x['index'] for x in arr]}"))
                except json.JSONDecodeError:
                    f.append(Finding("WARN", "guess.not_json", plain[:80]))
            elif name == "tguess":
                t = crypto.cryptojs_probe(blob)
                if t.get("ct_len", 0) % 16:
                    f.append(Finding("WARN", "tguess.pad", "tguess 密文非 16 字节整数倍"))
        rid = ca.headers.get("x-requested-id")
        if rid:
            try:
                crypto.cryptojs_decrypt(rid, crypto.requested_id_key(cap.session_token))
                f.append(Finding("OK", "requested_id.ok", "x-requested-id 可解"))
            except Exception as ex:
                f.append(Finding("ERROR", "requested_id.undecryptable",
                                 f"x-requested-id 解密失败: {type(ex).__name__}"))
    else:
        f.append(Finding("WARN", "session_token.absent",
                         "无 session token，跳过 guess/tguess/bio 解密校验"))

    # ---- TLS / akamai ----
    if not gt2.tls:
        f.append(Finding("WARN", "tls.absent", "无 TLS 指纹（JA3/Akamai）记录"))
    else:
        ja3 = gt2.tls.get("ja3_hash") or gt2.tls.get("akamai")
        if ja3:
            f.append(Finding("INFO", "tls.present", f"JA3/Akamai={ja3}"))

    # ---- 响应判定 ----
    ca_resp = ca.resp_json if isinstance(ca.resp_json, dict) else {}
    if ca_resp:
        if ca_resp.get("solved") is True:
            f.append(Finding("OK", "ca.solved", "solved=true"))
        elif ca_resp.get("error") == "DENIED ACCESS":
            f.append(Finding("ERROR", "ca.denied", "被服务端 DENIED ACCESS"))
        elif ca_resp.get("response") == "not answered":
            f.append(Finding("INFO", "ca.next", "还有下一题"))
    return f


# ---------------------------------------------------------------------------
def validate_fp(fp: dict) -> List[Finding]:
    """设备指纹自洽性：f/wh/n/c 是否与其余字段匹配。"""
    f: List[Finding] = []
    if not isinstance(fp, dict):
        return [Finding("ERROR", "fp.missing", "无设备指纹明文")]
    fe = fp.get("fe")
    if fe is not None:
        want = fp.get("f")
        matched = None
        for kind in ("x86", "x64"):
            if ahash.fp_fe_digest(fe, kind) == want:
                matched = kind
                break
        if matched:
            f.append(Finding("OK", "fp.f", f"f = murmur3-{matched}(fe) 自洽"))
        else:
            # 新版（如 2.18.x）算法/输入与旧文档不同，不硬判死
            f.append(Finding("WARN", "fp.f",
                             "f 与 murmur128(fe) 不匹配（新版 Arkose 算法或输入已变，非必然错误）"))
    if "n" in fp:
        try:
            sec = ahash.b64_unix_seconds_decode(fp["n"])
            import time as _t
            skew = abs(_t.time() - sec)
            f.append(Finding("OK" if skew < 300 else "WARN", "fp.n",
                             f"n 时间偏移 {skew:.0f}s"))
        except Exception:
            f.append(Finding("WARN", "fp.n", "n 不是合法 base64 秒级时间戳"))
    if fp.get("api_type") not in (None, "js"):
        f.append(Finding("WARN", "fp.api_type", f"api_type={fp.get('api_type')}"))
    for k in ("c",):
        if k in fp and not isinstance(fp[k], (str, dict, list)):
            f.append(Finding("WARN", f"fp.{k}", f"{k} 类型异常"))
    if "wh" in fp and isinstance(fp["wh"], str) and "|" not in fp["wh"]:
        f.append(Finding("WARN", "fp.wh", "wh 不是两段 murmur128 拼接"))
    return f
