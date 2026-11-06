"""Adobe 纯协议登录 · 端到端一条命令（无浏览器、无密码爆破）
   流程：
     [1] config / users / authenticationstate
     [2] POST /signin/v2/tokens?credential=password        -> challenge_required
     [3] POST /signin/v3/challenges?purpose=multiFactorAuthentication&factor=email&extendedAuthState=false
     [4] 从邮箱读 6 位验证码（Outlook OAuth）
     [5] POST /signin/v3/tokens?credential=code {purpose,code}      -> ★ SUSI token
     [6] POST /signin/v1/ims/tokens?clientId=<cid>  body={}  (Bearer) -> ★ IMS 凭证 token
     [7] POST {imsIdpUrl}/ims/fromSusi  (form)                      -> ★ ims_sid/aux_sid + access_token

用法：
  python tools/adobe_login_e2e.py --email DeniseMoore11259V@outlook.com --cid clio-playground-web
"""
import sys, os, json, re, argparse
sys.path.insert(0, ".")
from curl_cffi import requests as cr
from datetime import datetime, timezone, timedelta

S = "https://auth.services.adobe.com"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36")
ap = argparse.ArgumentParser()
ap.add_argument("--email", required=True)
ap.add_argument("--password", default="Adobe#2026Kx9")
ap.add_argument("--cid", default="clio-playground-web", help="授权 client_id（Firefly）")
ap.add_argument("--susi-cid", default="AdobeExpressWeb", help="SUSI 登录页 client_id")
ap.add_argument("--scope", default="openid,AdobeID,firefly_api,additional_info.roles")
ap.add_argument("--redirect", default="https://firefly.adobe.com/")
ap.add_argument("--wait", type=int, default=200)
ap.add_argument("--proxy", default=None)
ap.add_argument("--out", default="data/adobe/e2e.json")
a = ap.parse_args()

from tools.adobe_mail import load_accounts, refresh_access, wait_adobe
pool = {x["email"].lower(): x for x in load_accounts()}
mrec = pool.get(a.email.lower())
mail = refresh_access(mrec["client_id"], mrec["refresh"]) if mrec else None
print(f"账号 {a.email}  邮箱={'OK' if mail else '读不到'}")

s = cr.Session(impersonate="chrome")
if a.proxy:
    s.proxies = {"http": a.proxy, "https": a.proxy}
st = {}
R = S + "/signin"


def H(cid=None, extra=None):
    h = {"x-ims-clientid": cid or a.susi_cid,
         "content-type": "application/json;charset=UTF-8",
         "accept": "application/json, text/plain, */*", "origin": S,
         "referer": f"{S}/en_US/index.html?client_id={a.susi_cid}", "user-agent": UA}
    h.update({k: v for k, v in st.items() if v})
    h.update({k: v for k, v in (extra or {}).items() if v})
    return h


def C(tag, m, path, body=None, cid=None, extra=None):
    fn = {"POST": s.post, "PUT": s.put, "GET": s.get}[m]
    kw = {"headers": H(cid, extra), "timeout": 50}
    if m in ("POST", "PUT"):
        kw["data"] = body if isinstance(body, str) else json.dumps(body if body is not None else {})
    r = fn(R + path, **kw)
    for k in ("x-identity-verification-token", "x-ims-authentication-state-encrypted"):
        v = r.headers.get(k)
        if v:
            st[k] = v
    print(f"  [{tag}] {r.status_code} {r.text[:150]}")
    return r


print("[1] 引导")
C("config", "GET", f"/v2/configurations/{a.susi_cid}")
C("users", "POST", "/v2/users/accounts", {"username": a.email, "usernameType": "EMAIL"})
r = C("authstate", "POST", "/v1/authenticationstate",
      {"username": a.email, "usernameType": "EMAIL", "accountType": "individual"})

print("[2] 密码")
r = C("password", "POST", "/v2/tokens?credential=password",
      {"username": a.email, "password": a.password, "accountType": "individual",
       "rememberMe": True})
if r.status_code not in (200, 400):
    print("  ✗ 密码阶段异常"); sys.exit(1)

print("[3] 发验证码")
r = C("sendcode", "POST",
      "/v3/challenges?purpose=multiFactorAuthentication&factor=email&extendedAuthState=false", {})
if r.status_code != 200:
    print("  ✗ 发码失败:", r.text[:120]); sys.exit(1)

print("[4] 读邮箱")
since = (datetime.now(timezone.utc) - timedelta(seconds=25)).strftime("%Y-%m-%dT%H:%M:%SZ")
got = wait_adobe(mail, since, timeout=a.wait, want="Verification code") if mail else None
code = (got or {}).get("code")
print("  验证码 =", code)
if not code:
    print("  ✗ 未取到验证码"); sys.exit(1)

print("[5] 换 SUSI token")
r = C("v3/tokens?code", "POST", "/v3/tokens?credential=code",
      {"purpose": "multiFactorAuthentication", "code": code})
if r.status_code != 200:
    print("  ✗ 换 token 失败:", r.text[:150]); sys.exit(1)
susi = r.json().get("token", "")
print(f"  ✓ SUSI token {len(susi)}B")

print("[6] 铸 IMS 凭证 token")
r = s.post(f"{R}/v1/ims/tokens?clientId={a.susi_cid}",
           headers={**H(), "authorization": "Bearer " + susi}, data="{}", timeout=50)
print(f"  [{r.status_code}] {r.text[:120]}")
creds = (r.json() or {}).get("token") if r.status_code == 200 else None
if not creds:
    print("  ✗ 无 IMS 凭证"); sys.exit(1)
print(f"  ✓ IMS 凭证 {len(creds)}B")

print("[7] /ims/fromSusi → 会话 + access_token")
tokens = {}
for host in ("https://adobeid-na1.services.adobe.com", "https://ims-na1.adobelogin.com"):
    F = {"token": creds, "redirect_uri": a.redirect, "response_type": "token",
         "remember_me": "false", "flow": "signIn", "client_id": a.cid,
         "scope": a.scope, "locale": "en_US"}
    r = s.post(host + "/ims/fromSusi", data=F,
               headers={"user-agent": UA,
                        "content-type": "application/x-www-form-urlencoded",
                        "origin": S, "referer": S + "/"},
               timeout=50, allow_redirects=True)
    print(f"  {host} -> {r.status_code}")
    m = re.search(r"[#&](access_token|code)=([^&\s]+)", r.url + " " + r.text)
    if m:
        tokens[m.group(1)] = m.group(2)
        print(f"     ★ {m.group(1)} len={len(m.group(2))}")
    if "ims_sid" in [c.name for c in s.cookies.jar]:
        break

ck = [{"domain": c.domain, "name": c.name, "value": c.value} for c in s.cookies.jar]
hdr = "; ".join(f"{c['name']}={c['value']}" for c in ck)
out = {"email": a.email, "susi_token": susi, "ims_creds": creds, "tokens": tokens,
       "cookies": ck, "cookie_header": hdr}
json.dump(out, open(a.out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)

print("\n=== cookies ===")
for c in ck:
    print(f"  {c['domain']:38s} {c['name']:30s} len={len(c['value'])}")
print("\n=== tokens ===")
for k, v in tokens.items():
    print(f"  {k} = {str(v)[:100]}…")
print("\nCOOKIE 头:\n" + hdr[:1200])
print("\n->", a.out)
