# -*- coding: utf-8 -*-
"""Activate-only Arkose solver — wraps adobe_pure_protocol MatchGame.

stdin JSON:
  {
    "proxy": "socks5h://...",
    "ua": "...",
    "blob": "...",
    "yescaptcha_key": "...",
    "fp": { ... plaintext pack OR sealed overridden via c },
    "c": "optional pre-sealed c string",
    "pem": "optional RSA PEM",
    "public_key": "436DD567-...",
    "site": "https://auth.services.adobe.com",
    "surl": "arks-client.adobe.com"
  }
stdout JSON: {"ok": true, "token": "..."} | {"ok": false, "error": "..."}
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import traceback

def _resolve_pure() -> str:
    env = (os.environ.get("ADOBE_PURE_PROTOCOL") or "").strip()
    if env and os.path.isdir(env):
        return os.path.abspath(env)
    here = os.path.dirname(os.path.abspath(__file__))
    cands = [
        os.path.join(here, "adobe_pure_protocol"),
        os.path.join(here, "..", "adobe_pure_protocol"),
    ]
    data = (os.environ.get("DATA_DIR") or "").strip()
    if data:
        cands.insert(0, os.path.join(data, "activate", "adobe_pure_protocol"))
    for c in cands:
        c = os.path.abspath(c)
        if os.path.isdir(c):
            return c
    return ""


PURE = _resolve_pure()
if not PURE:
    print(json.dumps({"ok": False, "error": "adobe_pure_protocol not found (expected data/activate/adobe_pure_protocol)"}))
    raise SystemExit(2)
sys.path.insert(0, PURE)
# run_pow_worker.js / pow_solve.py resolve relative to this cwd
try:
    os.chdir(PURE)
except Exception:
    pass


PK_DEFAULT = "436DD567-5435-4B14-89A6-2F1188E11334"
UA_DEFAULT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36"
)


def main():
    req = json.load(sys.stdin)
    key = (req.get("yescaptcha_key") or "").strip()
    if not key:
        print(json.dumps({"ok": False, "error": "missing yescaptcha_key"}))
        return 2

    from arp.identity import impersonate_for_ua
    from arp.matchgame import MatchGame
    from arp.yescaptcha import classify

    pem = req.get("pem") or ""
    pem_path = os.path.join(PURE, "data", "re", "rsa_public.pem")
    if not pem and os.path.isfile(pem_path):
        pem = open(pem_path, encoding="utf-8").read()
    if not pem:
        print(json.dumps({"ok": False, "error": "missing pem"}))
        return 2

    fp = req.get("fp") or {}
    if not isinstance(fp, dict):
        fp = {}
    cc = req.get("c")
    # Prefer plaintext pack so MatchGame RSA-encrypts itself (same as adobe_register_pure).
    # A pre-sealed `c` from another stack can bind a mismatched fingerprint envelope.
    if isinstance(fp, dict) and fp.get("api_type"):
        cc = None
    if not fp:
        grab = os.path.join(PURE, "data", "grab_fresh.json")
        if os.path.isfile(grab):
            try:
                fp = json.load(open(grab, encoding="utf-8"))[0]["fp"]
            except Exception:
                fp = {}
    ua = req.get("ua") or UA_DEFAULT
    blob = req.get("blob") or ""
    proxy = req.get("proxy") or None
    pk = req.get("public_key") or PK_DEFAULT
    site = req.get("site") or "https://auth.services.adobe.com"
    surl = req.get("surl") or "arks-client.adobe.com"

    dump_dir = os.path.join(os.path.dirname(__file__))
    last_fail = None
    # Full MatchGame retries — a single wrong tile ends the session as solved=false.
    for attempt in range(3):
        mg = MatchGame(
            pk,
            site,
            surl=surl,
            ua=ua,
            proxy=proxy,
            blob=blob,
            fp_override=cc,
            node="node",
            capi_mode=req.get("capi_mode") or "lightbox",
            impersonate=impersonate_for_ua(ua),
        )
        s = mg.session()
        st = mg.gt2(s, fp, pem)
        if st.pow:
            if not mg.pows(s, st):
                last_fail = {"ok": False, "error": "pow failed", "attempt": attempt + 1}
                continue
        resp = mg.gfct(s, st)
        gd = resp.get("game_data") or {}
        cg = gd.get("customGUI") or {}
        instr = gd.get("instruction_string") or "icon_constellation"
        imgs = cg.get("_challenge_imgs") or resp.get("_challenge_imgs") or []
        if not imgs:
            last_fail = {"ok": False, "error": "gfct no image", "log": mg.log[-3:], "attempt": attempt + 1}
            continue

        try:
            mg.dapib(s, st)
        except Exception as e:
            last_fail = {"ok": False, "error": "dapib download: %s" % e, "attempt": attempt + 1}
            continue

        cur_instr = instr
        guesses, solved, final_rj = [], None, {}
        for rd in range(14):
            if not imgs:
                break
            raw = s.get(imgs[0], timeout=mg.timeout).content
            img_path = os.path.join(dump_dir, "chal_rd%d.png" % rd)
            open(img_path, "wb").write(raw)
            try:
                from PIL import Image
                w, _ = Image.open(img_path).size
                n_tiles = max(1, w // 200)
            except Exception:
                n_tiles = 6
            sol = classify(key, img_path, cur_instr)
            ssol = sol.get("solution") or {}
            objs = ssol.get("objects") or []
            confs = ssol.get("confidences") or []
            # Same as adobe_register_pure.solve_image: confidences argmax first.
            if confs:
                idx = int(max(range(len(confs)), key=lambda i: confs[i]))
            elif objs:
                idx = int(objs[0])
            else:
                last_fail = {"ok": False, "error": "classify failed", "sol": sol, "attempt": attempt + 1}
                solved = False
                break
            if idx >= n_tiles:
                idx %= n_tiles
            guesses.append({"index": idx})
            tg = mg.tguess_for(st, guesses)
            C = mg.ca(s, st, guesses, tguess=tg)
            rj = C.get("resp_json") or {}
            final_rj = rj
            open(os.path.join(dump_dir, "last_ca.json"), "w", encoding="utf-8").write(
                json.dumps(rj, ensure_ascii=False)
            )
            if str(rj.get("error", "")).upper().startswith("DENIED"):
                last_fail = {"ok": False, "error": "ca denied", "resp": rj, "attempt": attempt + 1}
                solved = False
                break
            # "not answered" + next challenge_image = this wave accepted, keep going.
            # Only stop when solved is explicitly true/false.
            if rj.get("solved") is not None:
                solved = rj.get("solved")
            _rc = rj.get("round_config") if isinstance(rj.get("round_config"), dict) else {}
            if _rc.get("instruction_string"):
                cur_instr = _rc["instruction_string"]
            imgs = rj.get("_challenge_imgs") or []
            if not imgs and _rc.get("challenge_image"):
                imgs = [_rc["challenge_image"]]
            if solved is not None:
                break
            if not imgs:
                last_fail = {"ok": False, "error": "no next image", "resp": rj, "guesses": guesses, "attempt": attempt + 1}
                solved = False
                break

        if solved is True:
            tok = final_rj.get("token") or st.token
            print(json.dumps({
                "ok": True, "token": tok, "session": st.session_token,
                "guesses": guesses, "attempt": attempt + 1,
            }))
            return 0
        last_fail = {
            "ok": False, "error": "not solved", "solved": solved,
            "guesses": guesses, "last": final_rj, "attempt": attempt + 1,
        }

    print(json.dumps(last_fail or {"ok": False, "error": "not solved"}))
    return 9


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as e:
        print(json.dumps({"ok": False, "error": str(e), "trace": traceback.format_exc()[-500:]}))
        raise SystemExit(1)
