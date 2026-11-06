"""统一身份（Identity）：TLS 指纹 / 请求头 / 设备指纹 三者必须来自同一个 profile。

要点（来自 arkose-fp-docs + 实测）：
  * accept-language 必须与设备指纹里的  L: / navigator_languages  一致
  * UA 必须与 uaData / user_agent_data_brands / platform / FOS / FB 一致
  * TLS(Akamai) 必须与 UA 的浏览器同代（curl_cffi impersonate 目标）
  * jsbd.DT 必须是真实目标页的 document.title（不能泄露我们自己的页）
"""
from __future__ import annotations

import json
import os
from typing import Dict, List, Optional

# Chrome 主版本 -> curl_cffi impersonate 目标（实测 Akamai 与真 Chrome 一致）
_IMPERSONATE = {
    "99": "chrome99", "100": "chrome100", "101": "chrome101", "104": "chrome104",
    "107": "chrome107", "110": "chrome110", "116": "chrome116", "119": "chrome119",
    "120": "chrome120", "123": "chrome123", "124": "chrome124", "131": "chrome131",
    "133": "chrome133a", "136": "chrome136", "142": "chrome142", "145": "chrome145",
    "146": "chrome146", "150": "chrome150", "151": "chrome151", "152": "chrome152",
}
DEFAULT_IMPERSONATE = "chrome"


def curl_proxy(proxy: Optional[str]) -> Optional[str]:
    """curl_cffi must resolve the name on the proxy (socks5h).

    socks5:// makes libcurl resolve locally and then speak TLS to the wrong
    hop, which Adobe and Cloudflare both reset (SSL_ERROR_SYSCALL /
    WRONG_VERSION_NUMBER). socks5h:// and http:// on the same port succeed.
    """
    if proxy and proxy.startswith("socks5://"):
        return "socks5h://" + proxy[len("socks5://"):]
    return proxy


def impersonate_for_ua(ua: str) -> str:
    """Highest curl_cffi Chrome profile that does not outrun the UA major."""
    major_s = chrome_major(ua)
    major = int(major_s) if major_s.isdigit() else 0
    available: List[tuple] = []
    try:
        from curl_cffi.requests.impersonate import BrowserType
        for b in BrowserType:
            v = str(getattr(b, "value", b))
            if not v.startswith("chrome") or "android" in v or "_" in v:
                continue
            digits = ""
            for ch in v[6:]:
                if ch.isdigit():
                    digits += ch
                else:
                    break
            if digits:
                available.append((int(digits), v))
    except Exception:
        available = [(int(k), v) for k, v in _IMPERSONATE.items() if k.isdigit()]
    available.sort()
    best = ""
    for n, v in available:
        if major and n <= major:
            best = v
    if not best and available:
        best = available[-1][1]
    return best or DEFAULT_IMPERSONATE

# 我们实测：curl_cffi 的这几档 Akamai 指纹 = 52d84b11737d980aef856699f885ca86（真 Chrome 一致）
AKAMAI_OK = "52d84b11737d980aef856699f885ca86"
AKAMAI_TEXT_OK = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"

DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36")


def chrome_major(ua: str) -> str:
    import re
    m = re.search(r"Chrome/(\d+)", ua or "")
    return m.group(1) if m else ""


def accept_language(languages: List[str], language: Optional[str] = None) -> str:
    """['en-US','en'] -> 'en-US,en;q=0.9'（与 Chrome 真机一致）"""
    langs = list(languages or ([language] if language else ["en-US"]))
    if not langs:
        langs = ["en-US"]
    out = [langs[0]]
    qs = [0.9, 0.8, 0.7, 0.6]
    for i, l in enumerate(langs[1:]):
        base = l.split("-")[0]
        out.append(f"{base};q={qs[i] if i < len(qs) else 0.5}")
    return ",".join(out)


def to_wire(pack) -> list:
    """转成 api.js 实际发送的线格式： [{key,value}, ...]（9 项）。

    真 c 明文（实测 data/fp_pack.json）：
      api_type  str
      f         str
      n         str
      wh        str
      enhanced_fp  list[91] of {key,value}     ← 嵌套数组，不是 JSON 字符串！
      fe           list[23] of str
      ife_hash  str
      jsbd      str                            ← JSON 字符串
      c         str
    """
    if isinstance(pack, list):
        pack = {i["key"]: i["value"] for i in pack}
    ef = pack.get("enhanced_fp")
    if isinstance(ef, str):
        ef = json.loads(ef)
    if isinstance(ef, dict):
        ef = [{"key": k, "value": v} for k, v in ef.items()]
    fe = pack.get("fe")
    if isinstance(fe, str):
        fe = json.loads(fe)
    jsbd = pack.get("jsbd")
    if not isinstance(jsbd, str):
        jsbd = json.dumps(jsbd, separators=(",", ":"))
    order = ["api_type", "f", "n", "wh", "enhanced_fp", "fe", "ife_hash", "jsbd", "c"]
    vals = {"api_type": pack.get("api_type"), "f": pack.get("f"), "n": pack.get("n"),
            "wh": pack.get("wh"), "enhanced_fp": ef, "fe": fe,
            "ife_hash": pack.get("ife_hash"), "jsbd": jsbd, "c": pack.get("c")}
    return [{"key": k, "value": vals[k]} for k in order if vals.get(k) is not None]


class Identity:
    """一份完整的"同一台浏览器"身份。"""

    def __init__(self, profile: dict, pack: Optional[dict] = None, *,
                 doc_title: str = "Adobe ID", history_len: int = 2,
                 tls_impersonate: Optional[str] = None, fix: bool = True):
        self.profile = profile
        self.pack = pack
        self.doc_title = doc_title
        self.history_len = history_len
        self.ua = profile.get("userAgent") or DEFAULT_UA
        self.accept_language = accept_language(profile.get("languages"), profile.get("language"))
        major = chrome_major(self.ua)
        self.impersonate = tls_impersonate or _IMPERSONATE.get(major, DEFAULT_IMPERSONATE)
        if fix and self.pack is not None:
            self.fix_pack()

    # ------------------------------------------------------------------ 校验
    def audit(self) -> List[str]:
        """返回不一致项（空列表 = 完全自洽）"""
        bad: List[str] = []
        p = self.profile
        if self.pack is None:
            return ["no pack"]
        ef = self.pack.get("enhanced_fp")
        ef = json.loads(ef) if isinstance(ef, str) else ef
        ef = {i["key"]: i["value"] for i in ef} if isinstance(ef, list) and ef and isinstance(ef[0], dict) else ef
        fe = self.pack.get("fe")
        fe = json.loads(fe) if isinstance(fe, str) else fe
        dfemap = {}
        for x in fe:
            if isinstance(x, str) and ":" in x:
                k, v = x.split(":", 1)
                dfemap[k] = v
        # UA 一致性
        if dfemap.get("PK") != p.get("platform"):
            bad.append(f"platform: fe PK={dfemap.get('PK')} vs profile {p.get('platform')}")
        if str(ef.get("navigator_languages")) != ",".join(p.get("languages", [])):
            bad.append(f"languages: ef={ef.get('navigator_languages')} vs {','.join(p.get('languages', []))}")
        if dfemap.get("L") != p.get("language"):
            bad.append(f"fe L={dfemap.get('L')} vs profile {p.get('language')}")
        if str(ef.get("window_inner_width")) != str(p["win"]["iw"]):
            bad.append("window_inner_width 不一致")
        if str(ef.get("window_outer_height")) != str(p["win"]["oh"]):
            bad.append("window_outer_height 不一致")
        if str(ef.get("navigator_device_memory")) != str(p["deviceMemory"]):
            bad.append("navigator_device_memory 不一致")
        if str(dfemap.get("H")) != str(p["hardwareConcurrency"]):
            bad.append("fe H 不一致")
        if str(dfemap.get("S")) != f"{p['screen']['w']},{p['screen']['h']}":
            bad.append("fe S 不一致")
        if str(dfemap.get("AS")) != f"{p['screen']['aw']},{p['screen']['ah']}":
            bad.append("fe AS 不一致")
        if str(dfemap.get("TO")) != str(p["tzOffset"]):
            bad.append(f"fe TO={dfemap.get('TO')} vs tzOffset {p['tzOffset']}")
        if str(dfemap.get("PR")) != str(p["win"]["dpr"]):
            bad.append("fe PR 不一致")
        # jsbd
        j = self.pack.get("jsbd")
        j = json.loads(j) if isinstance(j, str) else j
        if isinstance(j, dict):
            if j.get("DT") != self.doc_title:
                bad.append(f"jsbd.DT={j.get('DT')!r} 应为 {self.doc_title!r}")
            if j.get("NWD") != "false":
                bad.append(f"jsbd.NWD={j.get('NWD')!r} 应为 'false'")
        return bad

    def fix_pack(self):
        """把 jsbd / fe / ef 里与 profile 冲突的字段对齐。"""
        p = self.profile
        pk = self.pack
        ef = pk.get("enhanced_fp")
        ef = json.loads(ef) if isinstance(ef, str) else ef
        if isinstance(ef, list) and ef and isinstance(ef[0], dict):
            ef = {i["key"]: i["value"] for i in ef}
        fe = pk.get("fe")
        fe = json.loads(fe) if isinstance(fe, str) else fe
        # ef 对齐
        ef["navigator_languages"] = ",".join(p.get("languages", []))
        ef["window_inner_width"] = p["win"]["iw"]
        ef["window_inner_height"] = p["win"]["ih"]
        ef["window_outer_width"] = p["win"]["ow"]
        ef["window_outer_height"] = p["win"]["oh"]
        ef["navigator_device_memory"] = p["deviceMemory"]
        # fe 对齐
        idx = {}
        for i, x in enumerate(fe):
            if isinstance(x, str) and ":" in x:
                idx[x.split(":", 1)[0]] = i
        def setfe(k, v):
            if k in idx:
                fe[idx[k]] = f"{k}:{v}"
        setfe("L", p.get("language"))
        setfe("PR", p["win"]["dpr"])
        setfe("S", f"{p['screen']['w']},{p['screen']['h']}")
        setfe("AS", f"{p['screen']['aw']},{p['screen']['ah']}")
        setfe("TO", p["tzOffset"])
        setfe("T", f"{p.get('maxTouchPoints', 0)},false,false")
        setfe("H", p["hardwareConcurrency"])
        if p.get("fonts"):
            setfe("JSF", ",".join(p["fonts"]))
        # jsbd
        pk["jsbd"] = json.dumps({"HL": self.history_len, "NCE": True, "DT": self.doc_title,
                                 "NWD": "false", "DMTO": 1, "DOTO": 1}, separators=(",", ":"))
        pk["enhanced_fp"] = [{"key": k, "value": v} for k, v in ef.items()]
        pk["fe"] = fe
        # 重算两个 murmur 摘要
        try:
            from .hash import fp_fe_digest, ife_digest
            pk["f"] = fp_fe_digest(fe)
            pk["ife_hash"] = ife_digest(fe)
        except Exception:
            pass
        return pk

    # ------------------------------------------------------------------ 请求头
    def api_headers(self, kind: str, *, origin: Optional[str] = None,
                    referer: Optional[str] = None, ms: int = 0, xri: Optional[str] = None,
                    extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        h = {
            "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
            "accept": "*/*",
            "user-agent": self.ua,
            "accept-language": self.accept_language,
        }
        if kind == "gt2":
            if origin:
                h["origin"] = origin
                h["referer"] = referer or (origin + "/")
        else:
            h["cache-control"] = "no-cache"
            h["x-requested-with"] = "XMLHttpRequest"
            h["x-newrelic-timestamp"] = str(ms)
            h["cookie"] = f"timestamp={ms}"
            if referer:
                h["referer"] = referer
            if xri:
                h["x-requested-id"] = xri
        if extra:
            h.update(extra)
        return h

    # ------------------------------------------------------------------ 构造
    @classmethod
    def from_profile(cls, path: str, pack: Optional[dict] = None, **kw) -> "Identity":
        return cls(json.load(open(path, encoding="utf-8")), pack, **kw)

    @classmethod
    def from_pool(cls, pool_dir: str, idx: int = 0, **kw) -> "Identity":
        import glob
        files = sorted(glob.glob(os.path.join(pool_dir, "*.jsonl")))
        n = 0
        for f in files:
            for line in open(f, encoding="utf-8"):
                if not line.strip():
                    continue
                if n == idx:
                    r = json.loads(line)
                    return cls(r["profile"], r["pack"], **kw)
                n += 1
        raise IndexError(f"池里没有第 {idx} 条")
