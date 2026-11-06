"""自检：验证这套代码在新机器上能跑通（不发注册请求、不消耗额度、不建号）。

    python selftest.py

会依次检查：Python 依赖 / node / 数据文件 / YesCaptcha 余额
最后做一次真实的 Arkose gt2+gfct（只握手取题，不建号）。
"""
from __future__ import annotations
import os
import sys
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
OK, BAD = [], []


def chk(name, fn):
    try:
        r = fn()
        OK.append(f"  ✓ {name}" + (f"  {r}" if r else ""))
        return True
    except Exception as e:
        BAD.append(f"  ✗ {name}  → {type(e).__name__}: {str(e)[:140]}")
        return False


print("=" * 74)
print("Adobe 纯协议工具链 自检")
print("=" * 74)

chk("python 版本", lambda: f"{sys.version.split()[0]}  ({sys.executable})")


def _deps():
    import curl_cffi
    v = getattr(curl_cffi, "__version__", "?")
    from PIL import Image  # noqa
    return f"curl_cffi {v} / Pillow OK"


chk("Python 依赖", _deps)


def _node():
    from arp.dapib import find_node
    n = find_node()
    import subprocess
    v = subprocess.run([n, "-v"], capture_output=True, text=True, timeout=20).stdout.strip()
    return f"{n}  {v}"


chk("node", _node)

FILES = [
    "data/re/rsa_public.pem",
    "data/raw_c.json",
    "data/grab_fresh.json",
    "data/adobe/accounts_hdr.json",
    "data/bfp/capture_full.json",
    "data/bfp/forter_token.json",
    "tools/re/run_pow_worker.js",
    "tools/re/run_dapib.js",
    "tools/re/pow_solve.py",
]


def _files():
    miss = [f for f in FILES if not os.path.exists(f)]
    if miss:
        raise FileNotFoundError("缺: " + ", ".join(miss))
    return f"{len(FILES)} 个关键文件齐全"


chk("数据/脚本文件", _files)


def _yes():
    sys.path.insert(0, "tools")
    key = os.environ.get("YESCAPTCHA_KEY") or ""
    if not key:
        # 内置默认 key（可被环境变量覆盖）
        try:
            src = open("tools/adobe_register_pure.py", encoding="utf-8").read()
            for ln in src.splitlines():
                if ln.strip().startswith("YES_KEY"):
                    key = ln.split("=", 1)[1].strip().strip('"').strip("'")
        except Exception:
            pass
    if not key:
        raise RuntimeError("没找到 YesCaptcha key（设 YESCAPTCHA_KEY 或改 adobe_register_pure.py）")
    from arp.yescaptcha import balance
    b = balance(key)
    return f"余额 {b.get('balance')}"


chk("YesCaptcha 打码服务", _yes)


def _mail():
    from tools.adobe_mail import load_accounts, ROOT
    a = load_accounts()
    return f"邮箱池 {len(a)} 个  (ROOT={ROOT})"


chk("邮箱池（可选）", _mail)


def _arkose():
    """真握手：gt2 + gfct，只取题不提交、不建号。"""
    from arp.matchgame import MatchGame
    PK = "436DD567-5435-4B14-89A6-2F1188E11334"
    UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
          "(KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36")
    cfg = json.load(open("data/raw_c.json", encoding="utf-8"))
    fp = json.load(open("data/grab_fresh.json", encoding="utf-8"))[0]["fp"]
    cc = None if "api_type" in cfg else (cfg.get("c") or cfg)
    mg = MatchGame(PK, "https://auth.services.adobe.com", surl="arks-client.adobe.com",
                   node="node", ua=UA, capi_mode="lightbox", fp_override=cc)
    s = mg.session()
    st = mg.gt2(s, fp, open("data/re/rsa_public.pem").read())
    if st.pow:
        mg.pows(s, st)
    r = mg.gfct(s, st)
    gd = r.get("game_data") or {}
    return f"gt2 ✓  gfct ✓  题型={gd.get('instruction_string')!r}"


chk("Arkose 真握手 (gt2+gfct)", _arkose)

print()
for l in OK:
    print(l)
for l in BAD:
    print(l)
print()
print(f"通过 {len(OK)} / {len(OK) + len(BAD)}")
if BAD:
    print("\n有失败项 —— 先修掉再跑注册。")
    sys.exit(1)
print("全绿 ✓  可以开始用了：  python tools/adobe_pipeline.py")
