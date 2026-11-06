"""Adobe 注册机（单号）—— 纯协议，一条命令注册一个可用 Adobe 账号。

用法:
  python tools/adobe_reg.py                      # 从 E:\\typesafe\\email.txt 自动取一个未用邮箱
  python tools/adobe_reg.py --email x@y.com      # 指定邮箱
  python tools/adobe_reg.py --password 'Xx#123'  # 指定密码
  python tools/adobe_reg.py --verify-only x@y.com

产出: data/adobe/registered.json（追加），并打印 email / password / userId
"""
from __future__ import annotations
import sys, os, json, argparse, subprocess, time
sys.path.insert(0, ".")
from curl_cffi import requests as cr

ROOT = os.environ.get("ADOBE_MAIL_ROOT") or r"E:\typesafe"   # ★ 可用环境变量覆盖
REG_DB = "data/adobe/registered.json"
S = "https://auth.services.adobe.com"
CID = "AdobeExpressWeb"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36")

ap = argparse.ArgumentParser()
ap.add_argument("--email", default="")
ap.add_argument("--password", default="Adobe#2026Kx9")
ap.add_argument("--first", default="John")
ap.add_argument("--last", default="Smith")
ap.add_argument("--solver", default="yes", choices=["yes", "model", "brute"])
ap.add_argument("--cfile", default="data/raw_c.json")
ap.add_argument("--proxy", default="")
ap.add_argument("--verify-only", default="")
ap.add_argument("--timeout", type=int, default=1200)
a = ap.parse_args()


def load_db():
    if os.path.exists(REG_DB):
        try:
            return json.load(open(REG_DB, encoding="utf-8"))
        except Exception:
            pass
    return {"accounts": []}


def save_db(db):
    json.dump(db, open(REG_DB, "w", encoding="utf-8"), ensure_ascii=False, indent=1)


def pool_unused():
    """从 E:\\typesafe\\email.txt 里挑一个没注册过的邮箱（跳过 key-email.txt 已用的）。"""
    from tools.adobe_mail import load_accounts
    # ★ 只排除【我们真的注册过 Adobe 的】邮箱。
    #   E:\typesafe\key-email.txt 里的"已用"标记与我们无关（实测那些邮箱在 Adobe 并不存在账号）。
    used = {x["email"].lower() for x in load_db()["accounts"]}
    for acc in load_accounts():
        if acc["email"].lower() not in used:
            return acc["email"]
    return None


def verify(email: str):
    """POST /signin/v2/users/accounts → 账号是否存在 + userId。"""
    s = cr.Session(impersonate="chrome")
    h = {"x-ims-clientid": CID, "content-type": "application/json;charset=UTF-8",
         "accept": "application/json, text/plain, */*", "origin": S,
         "referer": S + f"/en_US/index.html?client_id={CID}", "user-agent": UA}
    s.get(f"{S}/signin/v2/configurations/{CID}", headers=h, timeout=30)
    r = s.post(f"{S}/signin/v2/users/accounts", headers=h,
               data=json.dumps({"username": email, "usernameType": "EMAIL"}), timeout=30)
    try:
        arr = r.json()
    except Exception:
        arr = []
    if isinstance(arr, list) and arr:
        st = (arr[0].get("status") or {}).get("code")
        return {"exists": True, "status": st,
                "methods": [m.get("id") for m in (arr[0].get("authenticationMethods") or [])]}
    return {"exists": False}


if a.verify_only:
    print(json.dumps(verify(a.verify_only), ensure_ascii=False))
    raise SystemExit(0)

em = a.email or pool_unused()
if not em:
    print("✗ 邮箱池已无可用的未注册邮箱（E:\\typesafe\\email.txt）")
    raise SystemExit(1)
print(f"[注册机] 目标邮箱: {em}")

cmd = [sys.executable, "-u", "tools/adobe_register_pure.py",
       "--email", em, "--password", a.password,
       "--first", a.first, "--last", a.last,
       "--solver", a.solver, "--c-file", a.cfile,
       "--capi-mode", "lightbox",
       "--ak-site", "https://auth.services.adobe.com",
       "--ak-surl", "arks-client.adobe.com",
       "--dump", "data/adobe/reg_last.json"]
if a.proxy:
    cmd += ["--proxy", a.proxy]
t0 = time.time()
print("[注册机] 开始纯协议注册（Arkose 解题 + 建号）…")
p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                   timeout=a.timeout)
out = (p.stdout or "") + (p.stderr or "")
tail = "\n".join(out.strip().splitlines()[-6:])
print(tail)
ok = "账号已创建" in out
print(f"[注册机] 建号 {'成功 ✓' if ok else '失败 ✗'}  用时 {time.time()-t0:.0f}s")
if not ok:
    raise SystemExit(2)

v = verify(em)
print(f"[注册机] 验证: exists={v.get('exists')} status={v.get('status')} methods={v.get('methods')}")
db = load_db()
db["accounts"].append({"email": em, "password": a.password, "created_at": time.time(),
                       "verify": v, "ok": True})
save_db(db)
print(f"\n=== 账号 ===\nemail    : {em}\npassword : {a.password}"
      f"\nstatus   : {v.get('status')}  methods={v.get('methods')}"
      f"\n已记录  -> {REG_DB} ({len(db['accounts'])} 个)")
