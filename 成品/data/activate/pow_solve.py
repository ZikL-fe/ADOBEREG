"""Arkose PoW 的 32 核并行求解器。

stdin  : {"chunk": "<base64>", "targets": ["<sha512hex>", ...], "start": <int>}
stdout : {"ok": true, "nonces": [n0, n1, ...], "parts": <n>, "secs": <float>}

语义严格对齐 worker 的 V()/n()：
    part_j  = split_n(chunk, len(targets))[j]          （worker 的 g()）
    nonce_0 从 start 起找 sha512(part_0 + str(nonce)) == targets[0]
    nonce_j 从 nonce_{j-1} 起（worker: Y = j.k）
"""
from __future__ import annotations
import hashlib
import json
import multiprocessing as mp
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


def split_n(s: str, n: int):
    """worker 的 g(X,R)：B=ceil(len/R); X=X[:B*R]; 切成 R 段。"""
    if n <= 0:
        return []
    size = -(-len(s) // n)
    s = s[: size * n]
    return [s[i * size:(i + 1) * size] for i in range(n)]


def _scan(a):
    """★ 用 digest() 比 bytes，而不是 hexdigest() 比 128 字符 hex 串：
    省掉每次哈希的 hex 构造开销（实测 ~1.3x）。"""
    part, target, lo, hi = a
    pb = part.encode("latin-1")
    tb = bytes.fromhex(target)
    h = hashlib.sha512
    for i in range(lo, hi):
        if h(pb + str(i).encode()).digest() == tb:
            return i
    return None


# ★ 实测数据（本机）：
#     线程池：无收益甚至更慢（hashlib 小输入不释放 GIL）——8 线程 646k < 1 线程 1064k
#     进程池：w=8 + step=200k 全面最优
#        0.5M→0.16s | 2M→0.25s | 10M→1.10s   （顺序分别 0.37/1.44/7.31）
#     池必须【复用】：每 split 新建一次会重复付 spawn 成本（之前 4~7s 的主因）
# ★ 关键坑：mp.Pool 的 imap_unordered 提前 return 后，池里剩余任务仍在后台排队，
#   下一次 find() 会继承积压 ⇒ 实测 split_ms=[120,1037,1067,1163,1044]（第一段快，之后都 ~1s）。
#   换成 ProcessPoolExecutor + 找到即 cancel() 未启动任务，彻底消除积压。
import concurrent.futures as _cf

_WORKERS = int(os.environ.get("POW_WORKERS", "8"))
_STEP = int(os.environ.get("POW_STEP", "150000"))
_EX = None


def _ex():
    global _EX
    if _EX is None:
        _EX = _cf.ProcessPoolExecutor(max_workers=_WORKERS)
    return _EX


def find(part: str, target: str, start: int, span: int, workers: int,
         step: int | None = None) -> int | None:
    """在 [start, start+span) 找 nonce；细切分 + 命中即取消剩余任务。"""
    st = step or _STEP
    n = max(1, span // st)
    futs = [_ex().submit(_scan, (part, target, start + k * st, start + (k + 1) * st))
            for k in range(n)]
    try:
        for f in _cf.as_completed(futs):
            r = f.result()
            if r is not None:
                return r
    finally:
        for f in futs:
            f.cancel()
    return None


def main():
    req = json.load(sys.stdin)
    chunk = req["chunk"]
    targets = req["targets"]
    start = int(req.get("start", 0))
    span = int(req.get("span", 8_000_000))
    workers = int(req.get("workers", int(os.environ.get("POW_WORKERS", "8"))))
    span = max(span, 64_000_000)   # ★ 实测服务端最远放到 11M+，留足余量；cancel 让多余任务几乎免费
    t0 = time.time()
    parts = split_n(chunk, len(targets))
    _t_pool = time.time(); _ex(); _pool_ms = round((time.time() - _t_pool) * 1000)
    nonces, y, _tms = [], start, []
    for j, (p, t) in enumerate(zip(parts, targets)):
        _tj = time.time()
        n = find(p, t, y, span, workers)
        _tms.append(round((time.time() - _tj) * 1000))
        if n is None:
            print(json.dumps({"ok": False, "failed_split": j, "from": y, "span": span}))
            return 1
        # ★ 硬自检：必须 sha512(part+nonce) == target
        if hashlib.sha512(p.encode("latin-1") + str(n).encode()).hexdigest() != t:
            print(json.dumps({"ok": False, "verify": j}))
            return 1
        nonces.append(n)
        y = n
    print(json.dumps({"ok": True, "nonces": nonces, "parts": len(parts),
                      "secs": round(time.time() - t0, 3),
                      "span_used": [nonces[0] - start] + [nonces[i + 1] - nonces[i]
                                                          for i in range(len(nonces) - 1)],
                      "pool_ms": _pool_ms, "split_ms": _tms, "nparts": len(parts), "span": span}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
