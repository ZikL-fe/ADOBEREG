"""Adobe 全链路：取号 → 注册 → 登录 → 输出 cookie + access_token（纯协议，无浏览器）。

用法:
  python tools/adobe_pipeline.py                     # 全自动跑一个新号
  python tools/adobe_pipeline.py --email x@y.com     # 指定邮箱（未注册则先注册）
  python tools/adobe_pipeline.py --login-only x@y.com
  python tools/adobe_pipeline.py --cid clio-playground-web --scope "openid,AdobeID,firefly_api"

产物: data/adobe/pipeline_<email>.json
      {email, password, user_id, access_token, cookie_header, cookies, susi_token, ims_creds}
"""
from __future__ import annotations
import sys, os, json, argparse, subprocess, time, re
sys.path.insert(0, ".")

S = "https://auth.services.adobe.com"
CID_SUSI = "AdobeExpressWeb"
REG_DB = "data/adobe/registered.json"

ap = argparse.ArgumentParser()
ap.add_argument("--email", default="")
ap.add_argument("--password", default="Adobe#2026Kx9")
ap.add_argument("--cid", default="clio-playground-web", help="授权 client_id")
ap.add_argument("--scope", default="openid,AdobeID,firefly_api,additional_info.roles")
ap.add_argument("--login-only", default="")
ap.add_argument("--skip-register", action="store_true")
ap.add_argument("--solver", default="yes", choices=["yes", "model", "brute"])
ap.add_argument("--proxy", default="")
ap.add_argument("--wait", type=int, default=200)
ap.add_argument("--timeout", type=int, default=1800)
ap.add_argument("--reg-retries", type=int, default=5)
a = ap.parse_args()


def run(cmd, timeout):
    p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                       errors="replace", timeout=timeout)
    return (p.stdout or "") + (p.stderr or ""), p.returncode


def db_load():
    if os.path.exists(REG_DB):
        try:
            return json.load(open(REG_DB, encoding="utf-8"))
        except Exception:
            pass
    return {"accounts": []}


def db_save(db):
    json.dump(db, open(REG_DB, "w", encoding="utf-8"), ensure_ascii=False, indent=1)


def pick_email():
    from tools.adobe_mail import load_accounts
    used = {x["email"].lower() for x in db_load()["accounts"]}
    for acc in load_accounts():
        if acc["email"].lower() not in used:
            return acc["email"]
    return None


# ---------------- 1) 注册 ----------------
em = a.login_only or a.email or pick_email()
if not em:
    print("✗ 邮箱池已无可注册邮箱"); raise SystemExit(1)
print(f"═══ 目标账号: {em} ═══")

need_reg = True
if a.login_only or a.skip_register:
    need_reg = False
if need_reg:
    known = {x["email"].lower() for x in db_load()["accounts"]}
    if em.lower() in known:
        print("[注册] 该邮箱已在本机注册库中，跳过注册")
        need_reg = False

if need_reg:
    print("\n──────────── 注册链路 ────────────")
    cmd = [sys.executable, "-u", "tools/adobe_register_pure.py",
           "--email", em, "--password", a.password,
           "--solver", a.solver, "--c-file", "data/raw_c.json",
           "--capi-mode", "lightbox",
           "--ak-site", S, "--ak-surl", "arks-client.adobe.com",
           "--dump", "data/adobe/reg_last.json"]
    if a.proxy:
        cmd += ["--proxy", a.proxy]
    ok = False
    for att in range(a.reg_retries):
        t0 = time.time()
        out, rc = run(cmd, a.timeout)
        print("\n".join(out.strip().splitlines()[-6:]))
        ok = "账号已创建" in out
        print(f"[注册] 第{att+1}次 {'成功 ✓' if ok else '失败 ✗'}  用时 {time.time()-t0:.0f}s")
        if ok:
            break
        print("   重试…")
    if not ok:
        print("✗ 注册多次失败（Arkose 解题未过）"); raise SystemExit(2)
    db = db_load()
    if not any(x["email"].lower() == em.lower() for x in db["accounts"]):
        db["accounts"].append({"email": em, "password": a.password, "created_at": time.time()})
        db_save(db)

# ---------------- 2) 登录 ----------------
print("\n──────────── 登录链路 ────────────")
outj = f"data/adobe/pipeline_{em.split('@')[0]}.json"
cmd = [sys.executable, "-u", "tools/adobe_login_e2e.py",
       "--email", em, "--password", a.password, "--cid", a.cid,
       "--scope", a.scope, "--wait", str(a.wait), "--out", outj]
if a.proxy:
    cmd += ["--proxy", a.proxy]
out, rc = run(cmd, a.timeout)
for ln in out.strip().splitlines():
    if re.search(r"\[(config|users|authstate|password|sendcode)|验证码|SUSI token|IMS 凭证|access_token|✓|✗", ln):
        print("  " + ln.strip()[:150])

if not os.path.exists(outj):
    print("✗ 登录失败（无输出）"); raise SystemExit(3)
j = json.load(open(outj, encoding="utf-8"))
at = (j.get("tokens") or {}).get("access_token", "")
ck = {c["name"]: c["value"] for c in (j.get("cookies") or [])}

import base64
uid = ""
if at:
    try:
        p = at.split(".")[1]; p += "=" * (-len(p) % 4)
        uid = json.loads(base64.urlsafe_b64decode(p)).get("user_id", "")
    except Exception:
        pass

FMT = ("relay", "ftrset", "locale", "ims_sid", "aux_sid", "bims_sid", "sso_sid")
hdr = "; ".join(f"{n}={ck[n]}" if n in ck else f"{n}=<未获得>" for n in FMT)

res = {"email": em, "password": a.password, "user_id": uid,
       "access_token": at, "susi_token": j.get("susi_token"),
       "ims_creds": j.get("ims_creds"), "cookies": j.get("cookies"),
       "cookie_header": hdr, "cookie_header_raw": j.get("cookie_header"),
       "client_id": a.cid, "scope": a.scope}
json.dump(res, open(outj, "w", encoding="utf-8"), ensure_ascii=False, indent=1)

print("\n──────────── 结果 ────────────")
print(f"email        : {em}")
print(f"password     : {a.password}")
print(f"userId       : {uid or '(未取到)'}")
print(f"access_token : {len(at)}B   ({a.cid}, scope={a.scope})")
for n in FMT:
    print(f"  {n:10s} {'✓ '+str(len(ck[n]))+'B' if n in ck else '✗'}")
print("\ncookie（按 relay;ftrset;locale;ims_sid;aux_sid;bims_sid;sso_sid 顺序）:")
print(hdr)
print("\naccess_token:")
print(at)
print(f"\n-> {outj}")
