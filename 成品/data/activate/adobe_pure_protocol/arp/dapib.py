"""Arkose `tguess` —— 跑**真实的 dapib 脚本**得到，不重写算法。

背景（2026 实测，见 docs/ARKOSE_TGUESS.md）
-------------------------------------------
`/fc/ca/` 除了加密的 `guess`，还必须带 `tguess`；否则服务端一律回
`{"response":"not answered"}`（HTTP 200 但不算答案）。

`tguess` 的算法**不是猜出来的**，而是 gfct 返回里 `dapib_url` 指向的脚本算的：

    GET {gfct.dapib_url}          # 形如 /dapib/<region>/<uuid>/<seq>.js?expiry=..&mac=..

该脚本（每 session 多态，3~4KB，可读）逻辑：

    window.ae.answer = guesses.map(g => ({...g, [sid]: rand}))   # sid/rand = session_token 按 '.' 拆
    dapib 脚本执行 -> window.parent.ae.dapibReceive({tanswer: <变换后的数组>})

变换 = 「两轮 键重排 + 按字符码播种的 Fisher-Yates 洗牌」，
并给每个值追加后缀 `w`；**只有检测到 Node/prerender/无 activeElement 时**
`w` 才被设成随机 A-Z（反自动化），正常浏览器为空串。

本模块的立场和 PoW 一致：**执行真脚本**（`tools/re/run_dapib.js`），不重写变换。
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from typing import Any, List, Optional

_RUNNER = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "tools", "re", "run_dapib.js")


def build_answer(guesses: List[dict], session_token: str) -> List[dict]:
    """构造 dapib 的输入：每个 guess 追加 `{sid: rand}`（session_token 按 '.' 拆）。"""
    sid, _, rand = session_token.partition(".")
    out = []
    for g in guesses:
        o = dict(g)
        o[sid] = rand or "0"
        out.append(o)
    return out


def run_dapib(source: str, answer: List[dict],
              node: str = "node", timeout: int = 60) -> Any:
    """把真 dapib 脚本丢进 Node vm 执行，返回 `tanswer`。"""
    with tempfile.TemporaryDirectory() as d:
        sp = os.path.join(d, "dapib.js")
        ip = os.path.join(d, "in.json")
        with open(sp, "w", encoding="utf-8") as f:
            f.write(source)
        with open(ip, "w", encoding="utf-8") as f:
            json.dump(answer, f)
        r = subprocess.run([node, _RUNNER, sp, ip], capture_output=True,
                           text=True, timeout=timeout)
    if r.returncode != 0:
        raise RuntimeError(f"run_dapib failed: {r.stderr[:400]}")
    txt = (r.stdout or "").strip()
    if not txt or txt == "null":
        raise RuntimeError("run_dapib: 脚本未回传 tanswer")
    return json.loads(txt)


def find_node() -> str:
    """Windows/WSL 下找一个可用的 node。"""
    for c in ("node", "nodejs",
              "/mnt/d/nodejs/node.exe", r"D:\nodejs\node.exe"):
        try:
            subprocess.run([c, "-v"], capture_output=True, timeout=20, check=True)
            return c
        except Exception:
            continue
    return "node"
