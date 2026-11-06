"""真实设备指纹池（你说的 2300 套）。

存法：JSONL / JSON 数组 / 一个目录（每个 .json 一条）。
每条形如 {"id": "...", "fp": {...}, "meta": {...}} 或直接就是指纹 dict。

入池 / 取用都会做自洽校验：f == murmur128(fe)、n 是 base64 秒时间戳、wh 两段。
"""
from __future__ import annotations

import json
import random
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional

from . import crypto, hash as ahash
from .validate import Finding, validate_fp


@dataclass
class FpRecord:
    fp: dict
    id: str = ""
    meta: Dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {"id": self.id, "fp": self.fp, "meta": self.meta}


def _coerce(obj: dict, fallback_id: str) -> FpRecord:
    if "fp" in obj and isinstance(obj["fp"], dict):
        return FpRecord(fp=obj["fp"], id=str(obj.get("id", fallback_id)),
                        meta=obj.get("meta", {}))
    return FpRecord(fp=obj, id=fallback_id)


class FingerprintPool:
    def __init__(self, records: List[FpRecord]):
        self.records = records

    # ---- 载入 ----
    @classmethod
    def from_list(cls, items: List[dict]) -> "FingerprintPool":
        return cls([_coerce(o, f"fp{i:05d}") for i, o in enumerate(items)])

    @classmethod
    def load(cls, path: str | Path) -> "FingerprintPool":
        p = Path(path)
        if p.is_dir():
            recs: List[FpRecord] = []
            for f in sorted(p.glob("*.json")) + sorted(p.glob("*.jsonl")):
                recs.extend(cls.load(f).records)
            return cls(recs)
        text = p.read_text(encoding="utf-8", errors="replace")
        if p.suffix.lower() == ".jsonl" or "\n{" in text:
            items = [json.loads(ln) for ln in text.splitlines() if ln.strip()]
        else:
            obj = json.loads(text)
            items = obj if isinstance(obj, list) else obj.get("fingerprints", [obj])
        return cls.from_list(items)

    def save(self, path: str | Path) -> None:
        p = Path(path)
        with p.open("w", encoding="utf-8") as fh:
            for r in self.records:
                fh.write(json.dumps(r.as_dict(), ensure_ascii=False) + "\n")

    # ---- 校验 ----
    def validate_all(self, limit: Optional[int] = None) -> List[tuple]:
        out = []
        for r in self.records[:limit] if limit else self.records:
            fs = [f for f in validate_fp(r.fp) if f.level in ("ERROR", "WARN")]
            out.append((r.id, fs))
        return out

    def clean(self) -> "FingerprintPool":
        keep = []
        for r in self.records:
            if not [f for f in validate_fp(r.fp) if f.level == "ERROR"]:
                keep.append(r)
        return FingerprintPool(keep)

    def reseal(self) -> "FingerprintPool":
        """重算 f/wh/n，让指纹与 fe 自洽（n 用当前时间）。"""
        import time
        out = []
        for r in self.records:
            fp = dict(r.fp)
            if "fe" in fp:
                fp["f"] = ahash.fp_fe_digest(fp["fe"], "x86")
            if "window_keys" in (r.meta or {}):
                fp["wh"] = ahash.wh_digest(r.meta["window_keys"],
                                           r.meta.get("proto_keys"))
            if fp.get("n"):
                try:
                    ahash.b64_unix_seconds_decode(fp["n"])
                except Exception:
                    fp["n"] = ahash.b64_unix_seconds()
            out.append(FpRecord(fp=fp, id=r.id, meta=r.meta))
        return FingerprintPool(out)

    # ---- 取用 ----
    def __len__(self) -> int:
        return len(self.records)

    def __iter__(self) -> Iterator[FpRecord]:
        return iter(self.records)

    def get(self, key: str | int) -> FpRecord:
        if isinstance(key, int):
            return self.records[key]
        for r in self.records:
            if r.id == key:
                return r
        raise KeyError(key)

    def sample(self, n: int = 1, seed: Optional[int] = None) -> List[FpRecord]:
        rnd = random.Random(seed)
        return rnd.sample(self.records, min(n, len(self.records)))

    def index(self) -> Dict[str, FpRecord]:
        return {r.id: r for r in self.records}
