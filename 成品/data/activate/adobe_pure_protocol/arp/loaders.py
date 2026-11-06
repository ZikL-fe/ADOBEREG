"""三个来源的抓包/回显载入器。

支持格式：
  har    : Chrome DevTools / mitmproxy 导出的 .har
  simple : 本沙箱推荐格式（见 examples/*.json）
  form   : 原始 HTTP 文本（请求行+头+空行+urlencoded body），可多段
  netlog : Chrome net-export JSON（尽力提取，字段可能不全）

统一产出 arp.model.Capture。
"""
from __future__ import annotations

import json
import re
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional

from .model import Capture, Exchange, stage_of

# ---------------------------------------------------------------------------


def load(path: str | Path, name: Optional[str] = None,
         kind: Optional[str] = None) -> Capture:
    p = Path(path)
    text = p.read_text(encoding="utf-8", errors="replace")
    name = name or p.stem
    if kind is None:
        kind = _guess_kind(p, text)
    if kind == "har":
        cap = load_har(text, name)
    elif kind == "simple":
        cap = load_simple(text, name)
    elif kind == "form":
        cap = load_form(text, name)
    elif kind == "netlog":
        cap = load_netlog(text, name)
    else:
        raise ValueError(f"unknown kind: {kind}")
    cap.kind = kind
    _derive_session_token(cap)
    return cap


def _guess_kind(p: Path, text: str) -> str:
    if p.suffix.lower() == ".har":
        return "har"
    stripped = text.lstrip()
    if stripped[:1] in "[{":
        try:
            obj = json.loads(text)
        except Exception:
            return "form"
        if isinstance(obj, list):
            return "simple"
        if isinstance(obj, dict) and "log" in obj and "entries" in obj.get("log", {}):
            return "har"
        if isinstance(obj, dict) and "events" in obj and "constants" in obj:
            return "netlog"
        if isinstance(obj, dict) and "requests" in obj:
            return "simple"
        return "simple"
    return "form"


# ---------------------------------------------------------------------------
def _parse_qs(url: str) -> Dict[str, str]:
    q = urllib.parse.urlparse(url).query
    return {k: v[0] for k, v in urllib.parse.parse_qs(q, keep_blank_values=True).items()}


_PK_RX = re.compile(r"/public_key/([^/?#]+)")


def _augment_query(url: str, st: str, query: Dict[str, str]) -> Dict[str, str]:
    """public_key 在 path 里，不在 query，补进 query 才能逐字段 diff。"""
    if st == "gt2":
        m = _PK_RX.search(url or "")
        if m:
            query.setdefault("public_key", m.group(1))
    return query


def _parse_body(text: Optional[str], mime: str = "") -> Dict[str, str]:
    if not text:
        return {}
    if "json" in (mime or "").lower():
        try:
            obj = json.loads(text)
            if isinstance(obj, dict):
                return {k: v if isinstance(v, str) else json.dumps(v, ensure_ascii=False)
                        for k, v in obj.items()}
        except Exception:
            pass
    if "=" in text and not text.lstrip().startswith("{"):
        out: Dict[str, str] = {}
        for k, v in urllib.parse.parse_qsl(text, keep_blank_values=True):
            out[k] = v
        return out
    return {"_raw": text}


def _hdr_list_to_dict(headers) -> Dict[str, str]:
    d: Dict[str, str] = {}
    if isinstance(headers, dict):
        return {str(k).lower(): str(v) for k, v in headers.items()}
    for h in headers or []:
        if isinstance(h, dict) and "name" in h:
            d[str(h["name"]).lower()] = str(h.get("value", ""))
    return d


# ---------------------------------------------------------------------------
def load_har(text: str, name: str = "har") -> Capture:
    obj = json.loads(text)
    entries = obj.get("log", {}).get("entries", [])
    exs: List[Exchange] = []
    for e in entries:
        req = e.get("request", {})
        url = req.get("url", "")
        st = stage_of(url)
        if st == "other":
            continue
        resp = e.get("response", {})
        resp_text = (resp.get("content") or {}).get("text")
        resp_json = None
        if resp_text:
            try:
                resp_json = json.loads(resp_text)
            except Exception:
                resp_json = None
        exs.append(Exchange(
            stage=st,
            method=req.get("method", "POST"),
            url=url,
            headers=_hdr_list_to_dict(req.get("headers")),
            query=_augment_query(url, st, _parse_qs(url)),
            body=_parse_body((req.get("postData") or {}).get("text"),
                             (req.get("postData") or {}).get("mimeType", "")),
            raw_body=(req.get("postData") or {}).get("text"),
            status=resp.get("status"),
            resp_json=resp_json,
            resp_text=resp_text,
        ))
    return Capture(name=name, exchanges=exs, meta={"format": "har"})


def load_simple(text: str, name: str = "simple") -> Capture:
    obj = json.loads(text)
    if isinstance(obj, list):
        obj = obj[0] if obj else {}
    exs: List[Exchange] = []
    for r in obj.get("requests", []):
        url = r.get("url", "")
        st = r.get("stage") or stage_of(url)
        exs.append(Exchange(
            stage=st,
            method=r.get("method", "POST"),
            url=url,
            headers={str(k).lower(): str(v) for k, v in (r.get("headers") or {}).items()},
            query={**(_augment_query(url, st, _parse_qs(url)) if url else {}),
                   **(r.get("query") or {})},
            body={k: (v if isinstance(v, str) else json.dumps(v))
                  for k, v in (r.get("body") or {}).items()},
            raw_body=r.get("raw_body"),
            status=r.get("status"),
            resp_json=r.get("resp_json"),
            resp_text=r.get("resp_text"),
            tls=r.get("tls"),
            note=r.get("note", ""),
        ))
    return Capture(
        name=name, exchanges=exs,
        meta=obj.get("meta", {}),
        fp=obj.get("fp"),
        session_token=obj.get("session_token"),
    )


_BLOCK_RX = re.compile(r"(?m)^(GET|POST|PUT|OPTIONS)\s+(\S+)")


def load_form(text: str, name: str = "form") -> Capture:
    """解析一段/多段原始 HTTP 文本。"""
    marks = list(_BLOCK_RX.finditer(text))
    exs: List[Exchange] = []
    for i, m in enumerate(marks):
        end = marks[i + 1].start() if i + 1 < len(marks) else len(text)
        block = text[m.start():end].strip()
        lines = block.splitlines()
        head = lines[0]
        url = head.split()[1]
        st = stage_of(url)
        if st == "other":
            continue
        headers: Dict[str, str] = {}
        j = 1
        while j < len(lines) and lines[j].strip():
            if ":" in lines[j]:
                k, v = lines[j].split(":", 1)
                headers[k.strip().lower()] = v.strip()
            j += 1
        body_text = "\n".join(lines[j + 1:]).strip() or None
        exs.append(Exchange(
            stage=st, method=head.split()[0], url=url,
            headers=headers, query=_augment_query(url, st, _parse_qs(url)),
            body=_parse_body(body_text, headers.get("content-type", "")),
            raw_body=body_text,
        ))
    return Capture(name=name, exchanges=exs, meta={"format": "form"})


def load_netlog(text: str, name: str = "netlog",
                url_filter: str = "arkoselabs") -> Capture:
    """尽力从 Chrome net-export 提取请求行/头/body。"""
    obj = json.loads(text)
    events = obj.get("events", [])
    const = obj.get("constants", {})
    types = {v: k for k, v in (const.get("logEventTypes") or {}).items()}
    phases = const.get("logEventPhase") or {}
    pending: Dict[Any, Dict[str, Any]] = {}
    exs: List[Exchange] = []

    for ev in events:
        tname = types.get(ev.get("type"), "")
        src = ev.get("source", {})
        sid = src.get("id")
        p = ev.get("params", {}) or {}
        if tname in ("URL_REQUEST", "HTTP_TRANSACTION_READ_REQUEST_HEADERS",
                     "HTTP2_SESSION_SEND_HEADERS", "HTTP_TRANSACTION_SEND_REQUEST_HEADERS"):
            url = p.get("url") or p.get("request_line") or ""
            if url_filter and url_filter not in str(url):
                continue
            rec = pending.setdefault(sid, {"headers": {}, "url": url})
            if url:
                rec["url"] = url
            for h in (p.get("headers") or []):
                if isinstance(h, str) and ":" in h:
                    k, v = h.split(":", 1)
                    rec["headers"][k.strip().lower()] = v.strip()
                elif isinstance(h, list) and len(h) >= 2:
                    rec["headers"][str(h[0]).lower()] = str(h[1])
        elif tname in ("URL_REQUEST_HTTP_RESPONSE_CODE",):
            pass

    for rec in pending.values():
        url = rec.get("url", "")
        st = stage_of(url)
        if st == "other" or not url:
            continue
        exs.append(Exchange(stage=st, url=url, headers=rec["headers"],
                            query=_augment_query(url, st, _parse_qs(url))))
    return Capture(name=name, exchanges=exs, meta={"format": "netlog"})


# ---------------------------------------------------------------------------
def _derive_session_token(cap: Capture) -> None:
    """从 gt2 响应里取 token（| 第一段）以及 data[blob]。"""
    gt2 = cap.by_stage("gt2")
    if not gt2 or not isinstance(gt2.resp_json, dict):
        return
    tok = gt2.resp_json.get("token")
    if isinstance(tok, str) and "|" in tok:
        cap.session_token = cap.session_token or tok.split("|", 1)[0]
    if cap.meta.get("blob") is None and isinstance(gt2.resp_json.get("blob"), str):
        cap.meta["blob"] = gt2.resp_json["blob"]
