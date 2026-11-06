"""报告渲染：text / json / markdown / html。"""
from __future__ import annotations

import html as _html
import json
from typing import Dict, List

from .compare import CompareResult, Row
from .validate import Finding

BAD = {"DIFF", "MISSING", "EXPECTED"}


def _trunc(v, n: int = 60) -> str:
    if v is None:
        return "-"
    s = v if isinstance(v, str) else json.dumps(v, ensure_ascii=False)
    s = s.replace("\n", "\\n")
    return s if len(s) <= n else s[: n - 1] + "…"


def to_json(res: CompareResult, findings: Dict[str, List[Finding]]) -> str:
    return json.dumps({
        "sources": res.sources,
        "aligned_ratio": round(res.aligned(), 4),
        "counts": res.counts(),
        "rows": [r.as_dict() for r in res.rows],
        "fp_rows": [r.as_dict() for r in res.fp_rows],
        "findings": {k: [f.__dict__ for f in v] for k, v in findings.items()},
    }, ensure_ascii=False, indent=2)


def to_text(res: CompareResult, findings: Dict[str, List[Finding]]) -> str:
    out: List[str] = []
    out.append("=" * 78)
    out.append("ARKOSE 三来源对齐报告  (golden=对方校验 / solver=打码 / mine=沙箱)")
    out.append("=" * 78)
    src = " | ".join(res.sources)
    out.append(f"来源: {src}")
    out.append(f"对齐率: {res.aligned()*100:.1f}%   {res.counts()}")
    out.append("")

    bad = res.divergences()
    if bad:
        out.append(f"--- 差异 {len(bad)} 项 ---")
        hdr = f"{'字段':46} {'类别':8} {'状态':9} " + " ".join(
            f"{s[:10]:<12}" for s in res.sources)
        out.append(hdr)
        out.append("-" * len(hdr))
        for r in bad:
            out.append(
                f"{r.key:46} {r.category:8} {r.status:9} " +
                " ".join(f"{_trunc(r.values.get(s), 12):<12}" for s in res.sources)
            )
            if r.note:
                out.append(f"    ↳ {r.note}")
        out.append("")
    else:
        out.append("--- 无差异，三方完全对齐 ---\n")

    same = [r for r in res.rows + res.fp_rows if r.status == "SAME"]
    out.append(f"--- 一致 {len(same)} 项 ---")
    for r in same:
        out.append(f"  ✓ {r.key}" + (f"  ({r.note})" if r.note else ""))
    out.append("")

    for name, fs in findings.items():
        if not fs:
            continue
        out.append(f"--- 单来源自检: {name} ---")
        for f in fs:
            out.append("  " + str(f))
        out.append("")
    return "\n".join(out)


def to_markdown(res: CompareResult, findings: Dict[str, List[Finding]]) -> str:
    L: List[str] = []
    L.append("# Arkose 三来源对齐报告\n")
    L.append(f"- 来源: `{' | '.join(res.sources)}`")
    L.append(f"- 对齐率: **{res.aligned()*100:.1f}%**  {res.counts()}\n")
    L.append("## 差异项\n")
    L.append("| 字段 | 类别 | 状态 | " + " | ".join(res.sources) + " | 说明 |")
    L.append("|---|---|---|" + "---|" * len(res.sources) + "---|")
    for r in res.divergences():
        cells = " | ".join(f"`{_trunc(r.values.get(s), 40)}`" for s in res.sources)
        L.append(f"| `{r.key}` | {r.category} | **{r.status}** | {cells} | {r.note} |")
    L.append("")
    for name, fs in findings.items():
        if not fs:
            continue
        L.append(f"## 自检: {name}\n")
        for f in fs:
            L.append(f"- `{f.level}` **{f.code}** — {f.msg}")
        L.append("")
    return "\n".join(L)


def to_html(res: CompareResult, findings: Dict[str, List[Finding]]) -> str:
    def esc(x):
        return _html.escape("" if x is None else str(x))
    rows = []
    for r in res.divergences():
        tds = "".join(f"<td><code>{esc(_trunc(r.values.get(s), 48))}</code></td>"
                      for s in res.sources)
        rows.append(f"<tr class='{r.status}'><td><code>{esc(r.key)}</code></td>"
                    f"<td>{esc(r.category)}</td><td><b>{r.status}</b></td>{tds}"
                    f"<td>{esc(r.note)}</td></tr>")
    fnd = []
    for name, fs in findings.items():
        fnd.append(f"<h3>{esc(name)}</h3><ul>")
        for f in fs:
            fnd.append(f"<li><span class='{f.level}'>{f.level}</span> "
                       f"<code>{esc(f.code)}</code> {esc(f.msg)}</li>")
        fnd.append("</ul>")
    return f"""<!doctype html><meta charset="utf-8">
<title>Arkose 对齐报告</title>
<style>
 body{{font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;margin:24px;color:#111}}
 table{{border-collapse:collapse;width:100%}}
 th,td{{border:1px solid #ddd;padding:5px 8px;text-align:left;vertical-align:top}}
 th{{background:#f6f6f6}} code{{font-family:ui-monospace,Consolas,monospace;font-size:12px}}
 tr.DIFF{{background:#ffecec}} tr.MISSING{{background:#fff6e5}} tr.EXPECTED{{background:#eef4ff}}
 .ERROR{{color:#b00;font-weight:700}} .WARN{{color:#b60}} .OK{{color:#176}} .INFO{{color:#456}}
 .big{{font-size:22px;font-weight:700}}
</style>
<h1>Arkose 三来源对齐报告</h1>
<p>来源: <code>{esc(' | '.join(res.sources))}</code></p>
<p class='big'>对齐率 {res.aligned()*100:.1f}% &nbsp; {esc(res.counts())}</p>
<h2>差异项 ({len(res.divergences())})</h2>
<table><tr><th>字段</th><th>类别</th><th>状态</th>
{''.join(f'<th>{esc(s)}</th>' for s in res.sources)}<th>说明</th></tr>
{''.join(rows)}</table>
{''.join(fnd)}
"""
