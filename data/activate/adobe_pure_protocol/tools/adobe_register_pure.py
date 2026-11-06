"""Adobe 注册 —— 纯协议端到端（真 Adobe blob + 真解题 + 带 token 建号）。

流程:
  1) Adobe boot: configurations → users/accounts → domains/info → passwords/validity
  2) POST /signin/v2/accounts  → 400 captcha_required + 新鲜 blob(x-ims-captcha-encrypted)
                                + x-identity-verification-token(IVT) + authState
  3) Arkose: gt2(带 blob) → pows → gfct → 每题解题 → ca ... 直到 solved
  4) 再 POST /signin/v2/accounts，带头 x-ims-arkose-captcha-token: <arkose token> → 建号

用法:
  python tools/adobe_register_pure.py [--solver yes|model|brute] [--email x@y.com] [--proxy PX]
"""
import sys, os, json, time, random, string, argparse
sys.path.insert(0, ".")
from curl_cffi import requests as cr
from arp.matchgame import MatchGame

S = "https://auth.services.adobe.com"
CID = "AdobeExpressWeb"
PK_SIGNUP = "436DD567-5435-4B14-89A6-2F1188E11334"
YES_KEY = ""
TPL = json.load(open("data/adobe/accounts_hdr.json", encoding="utf-8"))

ap = argparse.ArgumentParser()
ap.add_argument("--email", default="")
ap.add_argument("--password", default="Adobe#2026Kx9")
ap.add_argument("--first", default="John")
ap.add_argument("--last", default="Smith")
ap.add_argument("--solver", default="yes", choices=["yes", "model", "brute"])
ap.add_argument("--model-path", default="data/model/set.pt")
ap.add_argument("--c-file", default="data/raw_c.json")
ap.add_argument("--proxy", default=None)
ap.add_argument("--ak-site", default="https://auth.services.adobe.com")
ap.add_argument("--capi-mode", default="lightbox")
ap.add_argument("--ak-surl", default="arks-client.adobe.com")
ap.add_argument("--dump", default="data/adobe/register_pure.json")
ap.add_argument("--cid", default="AdobeExpressWeb", help="SUSI client_id")
a = ap.parse_args()
CID = a.cid          # ★ 可切换 client_id（Firefly = clio-playground-web）

PX = {"http": a.proxy, "https": a.proxy} if a.proxy else None


def hdrs(extra=None):
    h = {"x-ims-clientid": CID, "content-type": "application/json;charset=UTF-8",
         "accept": "application/json, text/plain, */*", "origin": S,
         "referer": S + f"/en_US/index.html?client_id={CID}",
         "sec-ch-ua": '"Google Chrome";v="155", "Chromium";v="155", "Not(A:Brand";v="24"',
         "sec-ch-ua-mobile": "?0", "sec-ch-ua-platform": '"Windows"',
         "user-agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                        "(KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36")}
    if extra:
        h.update(extra)
    return h


def mk_body(em):
    b = json.loads(TPL["req"])
    b["account"]["email"] = em
    b["account"]["firstName"] = a.first
    b["account"]["lastName"] = a.last
    b["account"]["password"] = a.password
    return b


class IVT:
    """跟踪 x-identity-verification-token 链。"""

    def __init__(self):
        self.tok = None

    def upd(self, r):
        h = {k.lower(): v for k, v in r.headers.items()}
        t = h.get("x-identity-verification-token")
        if t:
            self.tok = t
        return h

    def h(self):
        return {"x-identity-verification-token": self.tok} if self.tok else {}


# ---------- 解题器 ----------
_MDL = None


def solve_image(path, instr, n_tiles):
    """返回要提交的 index（0-based）。"""
    if a.solver == "yes":
        from arp.yescaptcha import classify
        sol = classify(YES_KEY, path, instr)
        s = sol.get("solution") or {}
        objs = s.get("objects") or []
        if not objs:
            return None, sol
        if s.get("confidences"):
            idx = int(max(range(len(s["confidences"])), key=lambda i: s["confidences"][i]))
        else:
            idx = int(objs[0])
        return idx, s
    if a.solver == "model":
        global _MDL
        import numpy as np, torch
        from tools.train_set import load_puzzle, SetNet
        from PIL import Image
        if _MDL is None:
            ck = torch.load(a.model_path, map_location="cpu")
            _MDL = SetNet(ck["cin"]); _MDL.load_state_dict(ck["sd"]); _MDL.eval()
        W, _H = Image.open(path).size
        n = W // 200
        k, ts = load_puzzle(path, n, 125, _MDL and 96, True)
        with torch.no_grad():
            out = _MDL(torch.tensor(np.stack([k]), dtype=torch.float32),
                       torch.tensor(np.stack([np.stack(ts, 0)]), dtype=torch.float32))
        return int(out.argmax()), {"model": [round(float(x), 3) for x in out[0]]}
    return None, {}


def main():
    em = a.email or ("".join(random.choices(string.ascii_lowercase + string.digits, k=13)) + "@outlook.com")
    s = cr.Session(impersonate="chrome")
    if PX:
        s.proxies = PX
    ivt = IVT()
    out = {"email": em, "solver": a.solver, "steps": []}

    def rec(tag, r):
        h = ivt.upd(r)
        rec_ = {"tag": tag, "status": r.status_code, "ivt": bool(ivt.tok),
                "captcha": (h.get("x-ims-captcha-encrypted") or "")[:40],
                "authState": bool(h.get("x-ims-authentication-state-encrypted"))}
        out["steps"].append(rec_)
        return h

    print(f"[1] boot  email={em}")
    rec("config", s.get(f"{S}/signin/v2/configurations/{CID}", headers=hdrs(ivt.h()), timeout=30))
    r = s.post(f"{S}/signin/v2/users/accounts", headers=hdrs(ivt.h()),
               data=json.dumps({"username": em, "usernameType": "EMAIL"}), timeout=30)
    rec("dedupe", r)
    d = em.split("@")[1]
    rec("domain", s.get(f"{S}/signin/v3/domains/{d}/info", headers=hdrs(ivt.h()), timeout=30))
    rec("pwvalid", s.post(f"{S}/signin/v1/passwords/validity?existingUser=false",
                          headers=hdrs(ivt.h()), data=json.dumps({"password": a.password}), timeout=30))

    print("[2] 第一次建号（期望 captcha_required + 新鲜 blob）")
    r = s.post(f"{S}/signin/v2/accounts", headers=hdrs(ivt.h()), data=json.dumps(mk_body(em)), timeout=45)
    h = rec("accounts#1", r)
    blob = h.get("x-ims-captcha-encrypted")
    auth_state = h.get("x-ims-authentication-state-encrypted")
    dbg_id = h.get("x-debug-id") or ("".join(random.choices("0123456789abcdef", k=8)) +
                                     "-1111-4111-8111-" + "".join(random.choices("0123456789abcdef", k=12)))
    print(f"    {r.status_code} body={r.text[:80]!r} blob={len(blob or '')}B authState={len(auth_state or '')}B")
    if not blob:
        print("    ❌ 没有拿到 blob，无法继续（可能免码或风控拒绝）")
        json.dump(out, open(a.dump, "w"), indent=1); return 1
    out["blob_len"] = len(blob)

    print("[3] Arkose 解题（真 blob）")
    _cfg = json.load(open(a.c_file, encoding="utf-8"))
    if "api_type" in _cfg:
        # ★ c_file 里是【解密后的明文 pack】⇒ 必须让 build_gt2 用 RSA 加密成真 c
        #   （否则发出去的是 52 字符的 "Copyright..." 假 c ⇒ token 无指纹绑定 ⇒ Adobe 拒绝）
        fp = _cfg
        cc = None
        print(f"    指纹: 明文 pack 已加载 ⇒ 将自行 RSA 加密（增强项 {len(_cfg.get('enhanced_fp') or [])} 个）")
    else:
        fp = json.load(open("data/grab_fresh.json", encoding="utf-8"))[0]["fp"]
        cc = _cfg.get("c") or _cfg
    pem = open("data/re/rsa_public.pem").read()
    _UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
           "(KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36")
    mg = MatchGame(PK_SIGNUP, a.ak_site, surl=a.ak_surl, node="node",
                   ua=_UA, capi_mode=a.capi_mode, fp_override=cc, blob=blob, proxy=a.proxy)
    s2 = mg.session()
    st = mg.gt2(s2, fp, pem)
    print(f"    gt2 ok pow={st.pow} session={st.session_token[:34]}")
    if st.pow:
        print("    pows ->", mg.pows(s2, st))
    resp = mg.gfct(s2, st)
    gd = resp.get("game_data") or {}
    cg = gd.get("customGUI") or {}
    instr = gd.get("instruction_string")
    waves = gd.get("waves")
    imgs = cg.get("_challenge_imgs") or resp.get("_challenge_imgs") or []
    print(f"    gfct instr={instr!r} waves={waves} imgs={len(imgs)}")
    if not imgs:
        print("    ❌ gfct 无图"); json.dump(out, open(a.dump, "w"), indent=1); return 2

    cur_instr = instr          # ★ 每轮题型（lightbox 链会换题型）
    guesses, solved, final_rj = [], None, {}
    for rd in range(14):
        if not imgs:
            break
        raw = s2.get(imgs[0], timeout=mg.timeout).content
        p = f"data/img/reg_rd{rd}.png"
        open(p, "wb").write(raw)
        from PIL import Image
        W, _H = Image.open(p).size
        n_tiles = W // 200
        idx, info = solve_image(p, cur_instr, n_tiles)
        if idx is None:
            print(f"    rd{rd} 解题失败: {json.dumps(info, ensure_ascii=False)[:140]}")
            break
        print(f"    rd{rd} 图 {len(raw)}B n={n_tiles} -> idx={idx} {json.dumps(info,ensure_ascii=False)[:70]}")
        if rd == 0:
            try:
                mg.dapib(s2, st)
            except Exception:
                pass
        guesses.append({"index": idx})
        tg = mg.tguess_for(st, guesses)
        C = mg.ca(s2, st, guesses, tguess=tg)
        rj = C.get("resp_json") or {}
        final_rj = rj
        print(f"        ca {C['status']} response={rj.get('response')} solved={rj.get('solved')}")
        if rd == 0:
            print(f"        响应字段: {list(rj.keys())}")
        if rj.get("solved") is not None:
            solved = rj.get("solved")
        _rc = rj.get("round_config") if isinstance(rj.get("round_config"), dict) else {}
        if _rc.get("instruction_string"):
            cur_instr = _rc["instruction_string"]
            print(f"        → 下一轮题型 = {cur_instr}")
        imgs = rj.get("_challenge_imgs") or []
        if not imgs and _rc.get("challenge_image"):
            imgs = [_rc["challenge_image"]]
        if solved is not None:
            break
    out["solved"] = solved
    out["guesses"] = guesses
    print(f"    ==> solved={solved}")
    if solved is not True:
        print("    ❌ 未通过 Arkose")
        json.dump(out, open(a.dump, "w"), indent=1); return 3

    token_full = st.token
    cands = []
    for name, tv in (("ca.token", final_rj.get("token")),
                     ("st.token(full)", token_full),
                     ("st.session_token", st.session_token)):
        if tv and tv not in [c[1] for c in cands]:
            cands.append((name, tv))
    print(f"[4] 建号 token 候选: " + ", ".join(f"{n}(len={len(v)})" for n, v in cands))
    print(f"    debug_id={dbg_id}")
    # Arkose 会话 cookie（浏览器里两个域同 jar，纯协议需手动带上）
    ark_cookies = {}
    try:
        for ck in s2.cookies.jar:
            ark_cookies[ck.name] = ck.value
    except Exception:
        pass
    print(f"    Arkose cookies: {list(ark_cookies.keys())}")
    variants = []
    for tname, token in cands:
        for hname in ("X-IMS-EntCaptcha-Response", "x-ims-ent-captcha-response",
                      "x-ims-arkose-captcha-token", "x-ims-captcha-token"):
            variants.append((f"{tname}+{hname}", token, hname, {}))
    # 附加调试变体（只用完整 token）
    try:
        _ft = json.load(open("data/bfp/forter_token.json", encoding="utf-8"))
        _tos = [t["detail"] for t in (_ft.get("forter") or {}).get("tokens", [])]
        _arp = _tos[0] if _tos else None
    except Exception:
        _arp = None
    print(f"    arp_token 候选: {str(_arp)[:46]}")
    if cands:
        tname, tok = cands[0]
        variants += [
            ("+x-debug-id", tok, "x-ims-arkose-captcha-token", {"x-debug-id": dbg_id}),
            ("+debug+cookie", tok, "x-ims-arkose-captcha-token", {"x-debug-id": dbg_id}),
            ("+blob-echo-hdr", tok, "x-ims-arkose-captcha-token", {"x-debug-id": dbg_id,
                                                                 "x-ims-captcha-encrypted": blob}),
        ]
        if _arp:
            variants += [
                ("+arp", tok, "x-ims-arkose-captcha-token", {"x-debug-id": dbg_id, "arp": _arp}),
                ("+arp(no quotes)", tok, "x-ims-arkose-captcha-token",
                 {"x-debug-id": dbg_id, "arp": _arp.strip('"')}),
            ]
    # ★ body 变体：Arkose token 可能作为 body 字段
    if cands:
        _tname, _tok = cands[0]
        for _k in ("captchaToken", "arkoseToken", "captchaSignUpToken"):
            variants.append((f"body.{_k}", _tok, "x-ims-arkose-captcha-token",
                             {"x-debug-id": dbg_id, "body_key": _k}))
    # ★★★ 三合一：Arkose + genuineToken(BFP) + arpToken(Forter) 同时发
    _gen = None
    try:
        _bb = json.load(open("data/bfp/capture_full.json", encoding="utf-8"))["bfp_req"]["post"]
        for _ in range(3):
            try:
                _r = s.post("https://idg.adobe.com/v1/api/bfp_capture",
                            headers={"content-type": "application/json",
                                     "x-api-key": "genuine-bfp-ims", "x-client-id": CID,
                                     "origin": S, "referer": S + f"/en_US/index.html?client_id={CID}"},
                            data=_bb, timeout=40)
                _gen = (_r.json() or {}).get("request_id")
                if _gen:
                    break
            except Exception:
                time.sleep(1.5)
    except Exception:
        pass
    print(f"    genuineToken(BFP request_id) = {str(_gen)[:40]}")
    if cands:
        _tname, _tok = cands[0]
        for _hn in ("X-IMS-EntCaptcha-Response", "x-ims-arkose-captcha-token"):
            _ex = {"x-debug-id": dbg_id, "ALL3": True}
            variants.append((f"ALL3({_hn})", _tok, _hn, _ex))
    for label, token, hname, extra in variants:   # body_variants
        ex = ivt.h()
        ex[hname] = token
        ex["x-debug-id"] = extra.get("x-debug-id", dbg_id)
        if auth_state:
            ex["x-ims-authentication-state-encrypted"] = auth_state
        if extra.get("arp"):
            ex["x-ims-arp-token"] = extra["arp"]
        if extra.get("ALL3"):
            if _gen:
                ex["x-ims-genuine-token"] = _gen
            if _arp:
                ex["x-ims-arp-token"] = _arp.strip('"')
            if auth_state:
                ex["x-ims-authentication-state-encrypted"] = auth_state
        if "x-ims-captcha-encrypted" in extra:
            ex["x-ims-captcha-encrypted"] = extra["x-ims-captcha-encrypted"]
        if ark_cookies and "cookie" not in label and "cookie" in label:
            pass
        reqsess = s if "cookie" not in label else None
        if reqsess is None:
            reqsess = cr.Session(impersonate="chrome")
            if PX:
                reqsess.proxies = PX
            for kk, vv in ark_cookies.items():
                try:
                    reqsess.cookies.set(kk, vv, domain=".adobe.com")
                except Exception:
                    pass
        try:
            _b = mk_body(em)
            if extra.get("body_key"):
                _b[extra["body_key"]] = token
            r = reqsess.post(f"{S}/signin/v2/accounts", headers=hdrs(ex),
                             data=json.dumps(_b), timeout=60)
        except Exception as e:
            print(f"    {label:34s}: EXC {type(e).__name__}")
            continue
        jj = {}
        try:
            jj = r.json()
        except Exception:
            pass
        ok = r.status_code in (200, 201, 202) and not jj.get("errorCode")
        print(f"    {label:34s}: {r.status_code} err={jj.get('errorCode')} "
              f"{'★★★ 账号已创建!!' if ok else ''}")
        out.setdefault("create_headers", []).append(
            {"variant": label, "status": r.status_code, "error": jj.get("errorCode"),
             "body": r.text[:300], "ok": ok})
        if ok:
            out["created"] = True
            out["created_email"] = em
            break
    json.dump(out, open(a.dump, "w"), ensure_ascii=False, indent=1)
    print("->", a.dump)
    return 0 if out.get("created") else 4


if __name__ == "__main__":
    raise SystemExit(main())
