"""三来源逐字段对比引擎。

    golden (对方要校验的)  vs  solver (打码结果)  vs  mine (沙箱生成)

分类：
    SAME      三方一致（volatile 字段比形状）
    DIFF      至少两方存在但值不同
    MISSING   只在部分来源里出现
    EXPECTED  目录里要求、但某来源缺失
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from . import crypto
from .model import CATALOG, REQUEST_39, Capture, FieldSpec

SECRET_FIELDS = {
    "ca.body.guess", "ca.body.tguess", "ca.body.bio",
    "ca.header.x-requested-id", "gt2.body.c", "gt2.body.bda",
}
# 同一物件的两种命名：任一存在就不算缺失
ALIAS_GROUPS = [{"gt2.body.c", "gt2.body.bda"}]
VOLATILE_SHAPE_FIELDS = {
    "gt2.body.rnd", "gt2.header.x-ark-esync-value",
    "gfct.header.x-newrelic-timestamp", "ca.header.x-newrelic-timestamp",
}
# 明文里天然每次不同的字段：只比结构
PLAIN_VOLATILE = {
    "ca.body.tguess#plain", "ca.body.bio#plain",
    "ca.header.x-requested-id#plain",
}
# c 密文随机（IV/key 每次新），只能比结构
SHAPE_PREFIX = "#shape"


# ---------------------------------------------------------------------------
@dataclass
class Row:
    key: str
    category: str
    values: Dict[str, Any] = field(default_factory=dict)
    plain: Dict[str, Any] = field(default_factory=dict)
    status: str = "SAME"
    note: str = ""

    def as_dict(self) -> dict:
        return {
            "key": self.key, "category": self.category, "status": self.status,
            "values": self.values, "plain": self.plain, "note": self.note,
        }


@dataclass
class CompareResult:
    sources: List[str]
    rows: List[Row]
    fp_rows: List[Row] = field(default_factory=list)

    def counts(self) -> Dict[str, int]:
        c: Dict[str, int] = {}
        for r in self.rows + self.fp_rows:
            c[r.status] = c.get(r.status, 0) + 1
        return c

    def aligned(self) -> float:
        total = len(self.rows) + len(self.fp_rows)
        if not total:
            return 0.0
        bad = sum(v for k, v in self.counts().items() if k != "SAME")
        return (total - bad) / total

    def divergences(self) -> List[Row]:
        return [r for r in self.rows + self.fp_rows if r.status != "SAME"]


# ---------------------------------------------------------------------------
def _shape(v: Any) -> str:
    if v is None:
        return "null"
    if v == "undefined":
        return "undefined"
    if isinstance(v, str) and v.lstrip()[:1] in "{[":
        return _json_shape(v)
    s = v if isinstance(v, str) else json.dumps(v, ensure_ascii=False, sort_keys=True)
    if isinstance(v, (int, float)) or (isinstance(v, str) and v.isdigit()):
        return f"num(len={len(s)})"
    return f"str(len={len(s)})"


def _json_shape(v: Any) -> str:
    """保留键名/数组长度，叶子只留类型 —— 用来比较“结构是否同一版”。"""
    try:
        obj = json.loads(v) if isinstance(v, str) else v
    except Exception:
        return _plain_shape(v)

    def walk(x):
        if isinstance(x, dict):
            return {k: walk(val) for k, val in x.items()}
        if isinstance(x, list):
            return [walk(i) for i in x]
        if isinstance(x, bool):
            return "bool"
        if isinstance(x, (int, float)):
            return "num"
        if x is None:
            return "null"
        return "str"

    return json.dumps(walk(obj), ensure_ascii=False, sort_keys=True)


def _plain_shape(v: Any) -> str:
    s = v if isinstance(v, str) else json.dumps(v, ensure_ascii=False, sort_keys=True)
    return f"str(len={len(s)})" if not isinstance(v, (int, float)) else str(v)


def _norm(v: Any, category: str) -> Any:
    if category in ("volatile", "secret"):
        return _shape(v)
    if isinstance(v, (dict, list)):
        return json.dumps(v, ensure_ascii=False, sort_keys=True)
    return v


def _spec_index(baseline: Optional[List[FieldSpec]] = None) -> Dict[str, str]:
    idx = {}
    for s in (baseline or CATALOG):
        idx[f"{s.stage}.{s.where}.{s.name}"] = s.category
    for k in REQUEST_39:
        idx.setdefault(k, "value")
    return idx


# ---------------------------------------------------------------------------
def _decrypt_secrets(cap: Capture) -> Dict[str, Any]:
    """用 session token 解密 guess/tguess/bio/x-requested-id。"""
    out: Dict[str, Any] = {}
    tok = cap.session_token
    if not tok:
        return out
    for e in cap.exchanges:
        if e.stage != "ca":
            continue
        for name in ("guess", "tguess", "bio"):
            v = e.body.get(name)
            if not v:
                continue
            try:
                out[f"ca.body.{name}#plain"] = crypto.cryptojs_decrypt(v, tok)
            except Exception as ex:
                out[f"ca.body.{name}#plain"] = f"<decrypt failed: {type(ex).__name__}>"
        rid = e.headers.get("x-requested-id")
        if rid:
            try:
                out["ca.header.x-requested-id#plain"] = crypto.cryptojs_decrypt(
                    rid, crypto.requested_id_key(tok))
            except Exception as ex:
                out["ca.header.x-requested-id#plain"] = f"<decrypt failed: {type(ex).__name__}>"
    return out


def _c_shape(cap: Capture) -> Dict[str, Any]:
    gt2 = cap.by_stage("gt2")
    if not gt2:
        return {}
    c = gt2.body.get("c") or gt2.body.get("bda")
    if not c:
        return {}
    parts = crypto.split_arkose_c(c)
    if parts.get("format") == "cryptojs":
        return {
            "gt2.body.c#shape": {
                "format": "cryptojs",
                "ct_len": parts["ct_len"],
                "iv_hex_len": parts["iv_hex_len"],
                "salt_hex_len": parts["salt_hex_len"],
            }
        }
    return {
        "gt2.body.c#shape": {
            "format": "concat",
            "iv_b64_len": len(parts["iv_b64"]),
            "tag_b64_len": len(parts["tag_b64"]),
            "rsa_key_b64_len": len(parts["rsa_key_b64"]),
            "ct_len": parts["ct_len"],
        }
    }


# ---------------------------------------------------------------------------
def compare(captures: Dict[str, Capture],
            baseline: Optional[List[FieldSpec]] = None) -> CompareResult:
    sources = list(captures.keys())
    views = {n: c.view() for n, c in captures.items()}
    plains = {n: _decrypt_secrets(c) for n, c in captures.items()}
    shapes = {n: _c_shape(c) for n, c in captures.items()}

    for n in sources:
        views[n].update(shapes[n])
        views[n].update(plains[n])

    keys = []
    for n in sources:
        for k in views[n]:
            if k not in keys:
                keys.append(k)
    cat_idx = _spec_index(baseline)

    rows: List[Row] = []
    for k in keys:
        cat = cat_idx.get(k, _infer_category(k))
        vals = {n: views[n].get(k) for n in sources}
        present = {n: (k in views[n]) for n in sources}
        norm = {n: _norm(vals[n], cat) for n in sources}
        plain = {n: plains[n].get(k) for n in sources if k in plains[n]}

        status, note = _classify(present, norm, cat, sources)
        rows.append(Row(key=k, category=cat, values=vals, plain=plain,
                        status=status, note=note))

    # 目录里要求但三方都没有的字段
    for s in (baseline or CATALOG):
        key = f"{s.stage}.{s.where}.{s.name}"
        if key in keys:
            continue
        # 别名（c/bda）任一存在就不算缺失
        if any(key in grp and any(a in keys for a in grp) for grp in ALIAS_GROUPS):
            continue
        rows.append(Row(key=key, category=s.category,
                        values={n: None for n in sources},
                        status="EXPECTED", note="目录要求但三方均缺失"))

    fp_rows = _compare_fp(captures)
    _sort(rows)
    return CompareResult(sources=sources, rows=rows, fp_rows=fp_rows)


def _infer_category(key: str) -> str:
    if key.endswith(SHAPE_PREFIX):
        return "value"
    if key.endswith("#plain"):
        return "volatile" if key in PLAIN_VOLATILE else "value"
    if key in SECRET_FIELDS:
        return "secret"
    if key in VOLATILE_SHAPE_FIELDS:
        return "volatile"
    return "value"


def _classify(present: Dict[str, bool], norm: Dict[str, Any],
              cat: str, sources: List[str]):
    have = [n for n in sources if present[n]]
    if not have:
        return "EXPECTED", "三方均缺失"
    if len(have) < len(sources):
        miss = [n for n in sources if not present[n]]
        vals = {norm[n] for n in have}
        if len(vals) > 1:
            return "DIFF", f"{'+'.join(miss)} 缺失且其余不一致"
        return "MISSING", f"{'+'.join(miss)} 缺失"
    vals = {norm[n] for n in sources}
    if len(vals) == 1:
        if cat == "volatile":
            return "SAME", "形状一致(值按设计不同)"
        return "SAME", ""
    return "DIFF", "值不一致"


def _sort(rows: List[Row]) -> None:
    order = {"DIFF": 0, "MISSING": 1, "EXPECTED": 2, "SAME": 3}
    rows.sort(key=lambda r: (order.get(r.status, 9), r.key))


# ---------------------------------------------------------------------------
def _fp_category(key: str) -> str:
    name = key.split(".")[-1]
    if name == "c":
        return "secret"
    if name == "n":
        return "volatile"
    return "value"


def _flatten_fp(fp: dict, prefix: str = "fp") -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in fp.items():
        p = f"{prefix}.{k}"
        if isinstance(v, dict):
            out.update(_flatten_fp(v, p))
        else:
            out[p] = v
    return out


def _compare_fp(captures: Dict[str, Capture]) -> List[Row]:
    have = {n: _flatten_fp(c.fp) for n, c in captures.items() if isinstance(c.fp, dict)}
    if len(have) < 2:
        return []
    keys: List[str] = []
    for fp in have.values():
        for k in fp:
            if k not in keys:
                keys.append(k)
    rows: List[Row] = []
    for k in keys:
        vals = {n: have[n].get(k) for n in have}
        present = {n: (k in have[n]) for n in have}
        cat = _fp_category(k)
        norm = {n: _norm(vals[n], cat) for n in have}
        if not all(present.values()):
            st, note = "MISSING", "部分来源缺少该指纹项"
        elif len(set(map(str, norm.values()))) == 1:
            st = "SAME"
            note = "指纹项形状一致" if cat in ("volatile", "secret") else "设备指纹一致"
        else:
            st, note = "DIFF", "设备指纹不一致"
        rows.append(Row(key=k, category=cat, values=vals, status=st, note=note))
    order = {"DIFF": 0, "MISSING": 1, "EXPECTED": 2, "SAME": 3}
    rows.sort(key=lambda r: (order.get(r.status, 9), r.key))
    return rows
