"""Arkose PoW（pow 2.4.0）纯 Python 复现 —— 不依赖任何第三方。

从 worker（data/pow/worker0.js，表旋转 25 位后）逐行等价移植：

    m(list)  = trim 每个值 -> k()
    k(obj)   = passA(大小写互换) -> passB(再互换) -> passC(Levenshtein+Caesar)
               -> passD(对含 'd' 键再跑一遍)
    u(str)   = btoa(utf-16le bytes of str)
    D(s,n)   = 把 s 切成 n 段（最后一段吃掉余数）
    A(非零, tgt) = 从 startingNonce 起找 sha512(seed_chunk + nonce) == target

对账基线（真 worker 输出）：
    in  = [{"7fCsfo5zEzKZoeZB3B":"rywEIhJt4tAfOFBohC"}]
    out = [{"7fCsfo5zEzKZoeZB3B":"qxvDHgIsts@eNEAngB",
            "7fCsfo5zEzKZoeZB3Bd":"84","7fCsfo5zEzKZoeZB3Bdd":"4"}]
"""
from __future__ import annotations

import base64
import hashlib
import json
from typing import Dict, List, Sequence
from urllib.parse import quote

_WORKER_CACHE: dict = {}

ALPHA = "".join(chr(0x41 + i) for i in range(26))  # A..Z，对应 worker 的 h()


# --------------------------------------------------------------------------
# 基础映射
# --------------------------------------------------------------------------
def swap_case(s: str) -> str:
    out = []
    for ch in s:
        z = ord(ch)
        if 0x41 <= z <= 0x5A:
            out.append(chr(z + 0x20))
        elif 0x61 <= z <= 0x7A:
            out.append(chr(z - 0x20))
        else:
            out.append(ch)
    return "".join(out)


def levenshtein(a: str, b: str) -> int:
    n, m = len(a), len(b)
    prev = list(range(m + 1))
    for i in range(1, n + 1):
        cur = [i] + [0] * m
        for j in range(1, m + 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1,
                         prev[j - 1] + (0 if a[i - 1] == b[j - 1] else 1))
        prev = cur
    return prev[m]


def _btoa(s: str) -> str:
    return base64.b64encode(s.encode("latin-1")).decode("ascii")


def _js_encode_uri_component(s: str) -> str:
    return quote(s, safe="-_.!~*'()")


def _caesar(value: str, dist: int) -> str:
    out = []
    for ch in value:
        j = ord(ch) + dist
        if j > 0x7E:
            j -= 0x41
        out.append(chr(j))
    return "".join(out)


def _pass_cd(obj: Dict[str, str], dist_fn) -> Dict[str, str]:
    """Levenshtein + Caesar；对每个键写 key、key+'d'。

    注意：worker 用同一个对象就地改，Object.keys 先快照，
    所以新加的 'd' 键会在同一 pass 里被处理到（生成 'dd'），
    且 'd' 的值会被后面对原键的处理覆盖。这里严格照做。

    dist_fn(v): 第二个参数就是 worker 里的 h
      - passC 传 ALPHA（"A..Z"），距离=Levenshtein(btoa(enc(v)), A..Z)
      - passD 传的是**计时函数 h**（arity 0），I() 因此退化成
        U.length==0 -> M[len(x)][0] == len(x)，即 len(btoa(enc(v)))
    """
    keys = [str(k) for k in obj.keys()]
    for s in keys:
        b = obj[s]
        a = dist_fn(b)
        obj[s] = _caesar(b, a)
        obj[s + "d"] = str(a)
    return obj


def _dist_alpha(v: str) -> int:
    return levenshtein(_btoa(_js_encode_uri_component(v)), ALPHA)


def _dist_len(v: str) -> int:
    return len(_btoa(_js_encode_uri_component(v)))


def k(answers: List[Dict[str, str]]) -> List[Dict[str, str]]:
    R = [dict(o) for o in answers]
    R = [{kk: swap_case(vv) for kk, vv in o.items()} for o in R]   # passA
    R = [{kk: swap_case(vv) for kk, vv in o.items()} for o in R]   # passB
    R = [_pass_cd(dict(o), _dist_len) for o in R]                   # passC
    R = [_pass_cd(dict(o), _dist_len) for o in R]                   # passD
    return R


def _js_tostring(v) -> str:
    """JS 的 v.toString()（m() 里用的是 toString 不是 trim）。"""
    if isinstance(v, bool):
        return "true" if v else "false"
    if v is None:
        return "null"
    if isinstance(v, float) and v.is_integer():
        return str(int(v))
    return str(v)


def m(items) -> List[Dict[str, str]]:
    """worker 的 m()：每个值 v.toString()，再走 k()。"""
    converted = [{kk: _js_tostring(vv) for kk, vv in o.items()} for o in items]
    return k(converted)


# --------------------------------------------------------------------------
# 编码：u() / D()
# --------------------------------------------------------------------------
def u(s: str) -> str:
    """btoa(UTF-16LE bytes)。"""
    return base64.b64encode(s.encode("utf-16-le")).decode("ascii")


def split_n(s: str, n: int) -> List[str]:
    """worker 的 D(X,R)：
        size = ceil(len/R); X = X[:size*R]（超长自动截断）；再切 R 段。
    注意是 Math.ceil（不是 floor）：264/5 -> 53，前 4 段 53 + 末段 52。"""
    if n <= 0:
        return []
    size = -(-len(s) // n)          # ceil
    s = s[:size * n]
    return [s[i * size:(i + 1) * size] for i in range(n)]


def sha512_hex(data: str) -> str:
    return hashlib.sha512(data.encode("latin-1")).hexdigest()


# --------------------------------------------------------------------------
# 搜索：A()
# --------------------------------------------------------------------------
def solve_split(seed_chunk: str, target_hash: str, starting_nonce: int,
                timeout_s: float = 180.0) -> int:
    """找 nonce 使 sha512(seed_chunk + str(nonce)) == target_hash。

    服务端把答案放在 starting_nonce 之后的不远处（浏览器靠 crypto.subtle 也能过），
    hashlib 约 1.4M H/s，几百万区间秒级。"""
    import time
    pb = seed_chunk.encode("latin-1")
    i = int(starting_nonce)
    deadline = time.time() + timeout_s
    while True:
        for _ in range(50000):
            if hashlib.sha512(pb + str(i).encode()).hexdigest() == target_hash:
                return i
            i += 1
        if time.time() > deadline:
            raise TimeoutError(f"POW_TIMEOUT split@{starting_nonce}")


def _search_range(args):
    chunk, target, lo, hi = args
    pb = chunk.encode("latin-1")
    for i in range(lo, hi):
        if hashlib.sha512(pb + str(i).encode()).hexdigest() == target:
            return i
    return None


def solve_split_parallel(seed_chunk: str, target_hash: str, starting_nonce: int,
                         span: int = 200_000_000, workers: int | None = None) -> int | None:
    """多进程并行搜 [start, start+span)。找不到返回 None。

    服务端会给可疑客户端一个离答案很远的 starting_nonce，故需要大跨度 + 多核。
    """
    import multiprocessing as mp
    import os
    if workers is None:
        workers = max(1, (os.cpu_count() or 4) - 2)
    step = max(1, span // workers)
    ranges = [(seed_chunk, target_hash, starting_nonce + k * step,
               starting_nonce + (k + 1) * step) for k in range(workers)]
    pool = mp.Pool(workers)
    try:
        for res in pool.imap_unordered(_search_range, ranges):
            if res is not None:
                pool.terminate()
                return res
    finally:
        pool.terminate()
        pool.join()
    return None


def fetch_live_worker(setup: dict, *, surl: str = "arks-client.adobe.com",
                      proxy: str | None = None, out: str | None = None) -> str:
    """下载**当次**的 worker（polymorphic：每次会话构建不同，旧副本不通用）。"""
    from curl_cffi import requests as creq
    from .identity import curl_proxy
    s = creq.Session(impersonate="chrome")
    px = curl_proxy(proxy)
    if px:
        s.proxies = {"http": px, "https": px}
    js = s.get(setup["sequence"], timeout=40).text
    if out:
        with open(out, "w", encoding="utf-8") as f:
            f.write(js)
    return js


def run_pow_node(setup: dict, *, worker_js: str | None = None,
                 surl: str = "arks-client.adobe.com", proxy: str | None = None,
                 node_timeout: int = 240, scripts_dir: str = "tools/re") -> dict:
    """用**真 worker**（当次构建）在 Node 里算 —— 这是唯一可靠的做法：
    worker 是 polymorphic 的，每次会话的 m/k 变换不同，抄一份不通用。

    tools/re/run_pow_worker.js 把 crypto.subtle.digest 换成 Node createHash，
    实测 ~200k hash/s（原生 subtle 只有 ~60/s）。

    返回与 run_pow() 同形的 dict。
    """
    import json as _json
    import os
    import subprocess
    import tempfile
    if worker_js is None:
        # ★ 缓存：同一会话内 sequence URL 不变，但原来每轮都重新下载（~0.6s）
        _ck = setup.get("sequence") or ""
        if _ck and _ck in _WORKER_CACHE:
            worker_js = _WORKER_CACHE[_ck]
        else:
            worker_js = fetch_live_worker(setup, surl=surl, proxy=proxy)
            if _ck:
                _WORKER_CACHE[_ck] = worker_js
    msg = build_worker_message(setup)
    with tempfile.TemporaryDirectory() as td:
        wp = os.path.join(td, "worker.js")
        mp = os.path.join(td, "msg.json")
        open(wp, "w", encoding="utf-8").write(worker_js)
        open(mp, "w", encoding="utf-8").write(_json.dumps(msg))
        r = subprocess.run(
            ["node", os.path.join(scripts_dir, "run_pow_worker.js"), wp, mp],
            capture_output=True, text=True, timeout=node_timeout)
    try:
        j = _json.loads(r.stdout)
    except Exception:
        raise RuntimeError(f"node worker failed: {r.stderr[-300:] or r.stdout[-300:]}")
    if os.environ.get("POW_VERBOSE"):
        import sys as _sys
        _sys.stderr.write("[pow] " + (r.stderr or "").strip().replace("\n", " | ")[:300] + "\n")
    if not j.get("ok"):
        raise TimeoutError(f"POW_TIMEOUT(worker): {_json.dumps(j.get('errors'))[:200]}")
    dd = j["done"]["data"]
    hr = float(dd.get("hashRate", 0.0) or 0.0)
    tm = int(dd.get("time", 0) or 0)
    # ---- ★ 归一化上报值 ------------------------------------------------
    # 起了 jump 补丁后 worker 几乎不做哈希，hashRate 会飙到 ~1.9M、time 只剩 1ms，
    # 而真浏览器是 hashRate≈60~350（单位 = nonce/毫秒）、time≈dist/rate。
    # 这两个值要发给 /pows/check，量级差 4 个数量级太可疑 ⇒ 换回可信区间。
    # 注意：只改上报的两个标量，finalTransform / result 一字不动。
    if hr > 2000.0 or tm < 200:
        import random as _rnd
        _iters = [int(x.get("iterations", 0) or 0) for x in (dd.get("targetHashData") or [])]
        _start = int((setup.get("work_config") or {}).get("starting_nonce", 0) or 0)
        _dist = (max(_iters) - _start) if _iters else 0
        hr = round(_rnd.uniform(130.0, 360.0), 2)
        tm = max(400, int(_dist / hr)) if hr else tm
        dd["__normalized"] = {"dist": _dist, "orig_rate": dd.get("hashRate"),
                             "orig_time": dd.get("time")}
    return {
        "hashRate": hr,
        "time": tm,
        "finalTransform": dd["finalTransform"],
        "targetHashData": dd["targetHashData"],
        "result": [{"target_hash": x["targetHash"], "attempt_count": x["iterations"]}
                   for x in dd["targetHashData"]],
    }


def build_worker_message(setup: dict) -> dict:
    """按 runner 的 ft() 构造发给 worker 的消息。"""
    wc = setup["work_config"]
    return {"type": "start", "data": {
        "type": setup["work_type"],
        "itimeout": setup["timeout"],
        "seed": wc["seed"],
        "startingNonce": wc.get("starting_nonce", 0),
        "targetHashData": [{"targetHashData": s["target_hash"]} for s in wc.get("splits", [])],
    }}


def run_pow(setup: dict, *, timeout_s: float = 70.0, span: int = 200_000_000,
            parallel: bool = True) -> dict:
    """完整复现 worker 的计算，返回 /pows/check 需要的字段。

    -> {hashRate, time, finalTransform, targetHashData:[{iterations,targetHash}], result:[…]}
    """
    import time
    t0 = time.time()
    msg = build_worker_message(setup)
    seed = msg["data"]
    d = m(seed["seed"])                                  # m(answer)
    chunk = u(json.dumps(d, separators=(",", ":")))      # u(JSON.stringify(d))
    splits = seed["targetHashData"]
    parts = split_n(chunk, len(splits)) if splits else []
    xl = []
    nonce = seed["startingNonce"]
    for j, sp in enumerate(splits):
        if parallel:
            got = solve_split_parallel(parts[j], sp["targetHashData"], nonce, span)
            if got is None:
                raise TimeoutError(f"POW_TIMEOUT split{j}@{nonce} span={span}")
            nonce = got
        else:
            nonce = solve_split(parts[j], sp["targetHashData"], nonce, timeout_s)
        xl.append({"target": sp["targetHashData"], "xy": nonce})
    f = {i: xl[i]["xy"] for i in range(len(xl))}
    final = m([*d, f])
    elapsed = round((time.time() - t0) * 1000)
    total_iters = (xl[-1]["xy"] - seed["startingNonce"]) if xl else 0
    return {
        "hashRate": (total_iters / (elapsed / 1000.0)) if elapsed else 0.0,
        "time": elapsed,
        "finalTransform": final,
        "targetHashData": [{"iterations": x["xy"], "targetHash": x["target"]} for x in xl],
        "result": [{"target_hash": x["target"], "attempt_count": x["xy"]} for x in xl],
    }


def check_payload(setup: dict, computed: dict, session_token: str = "") -> dict:
    """按 runner 的 Ye() 组装 /pows/check 的 body。"""
    return {"pow_token": setup["pow_token"],
            "session_token": session_token or setup.get("session_token", ""),
            "hash_rate": computed["hashRate"],
            "execution_time": computed["time"],
            "transform": computed["finalTransform"],
            "result": computed["result"]}
