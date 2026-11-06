"""arp 命令行入口。

    python -m arp compare  --golden g.json --solver s.json --mine m.json
    python -m arp validate --capture c.json [--fp fp.json]
    python -m arp decrypt  --capture c.json [--field ca.body.tguess]
    python -m arp catalog
    python -m arp shape-c  --c "<c 字符串>"
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import crypto
from . import loaders
from . import report as rpt
from .compare import compare as run_compare
from .model import CATALOG, REQUEST_39
from .validate import validate as run_validate, validate_fp as run_validate_fp
from . import generate, fp_pool, keys as keys_mod


def _load_capture(path: str, name: str, kind: str | None):
    return loaders.load(path, name=name, kind=kind)


def cmd_compare(a) -> int:
    caps = {}
    for label, path in (("golden", a.golden), ("solver", a.solver), ("mine", a.mine)):
        if path:
            caps[label] = _load_capture(path, label, a.kind)
    if len(caps) < 2:
        print("至少需要两个来源", file=sys.stderr)
        return 2

    res = run_compare(caps)
    findings = {n: run_validate(c) for n, c in caps.items()}

    fmt = a.format
    if fmt == "json":
        text = rpt.to_json(res, findings)
    elif fmt == "md":
        text = rpt.to_markdown(res, findings)
    elif fmt == "html":
        text = rpt.to_html(res, findings)
    else:
        text = rpt.to_text(res, findings)

    if a.out:
        Path(a.out).write_text(text, encoding="utf-8")
        print(f"[arp] 报告已写入 {a.out}  (对齐率 {res.aligned()*100:.1f}%)")
    else:
        print(text)
    return 0 if not res.divergences() else 1


def cmd_validate(a) -> int:
    cap = _load_capture(a.capture, "capture", a.kind)
    findings = run_validate(cap)
    if a.fp:
        obj = json.loads(Path(a.fp).read_text(encoding="utf-8"))
        cap.fp = obj.get("fp", obj) if isinstance(obj, dict) else obj
    if getattr(cap, "fp", None):
        findings += run_validate_fp(cap.fp)
    for f in findings:
        print(f)
    bad = sum(1 for f in findings if f.level == "ERROR")
    print(f"\n[arp] ERROR={bad}  (共 {len(findings)} 条)")
    return 0 if bad == 0 else 1


def cmd_decrypt(a) -> int:
    cap = _load_capture(a.capture, "capture", a.kind)
    tok = a.token or cap.session_token
    if not tok:
        print("缺少 session token，请用 --token 指定", file=sys.stderr)
        return 2
    ca = cap.by_stage("ca")
    if not ca:
        print("capture 中无 ca 请求", file=sys.stderr)
        return 2
    fields = [a.field] if a.field else ["ca.body.guess", "ca.body.tguess", "ca.body.bio"]
    for key in fields:
        _, where, name = key.split(".", 2)
        blob = ca.body.get(name) if where == "body" else ca.headers.get(name)
        if not blob:
            print(f"{key}: <缺>")
            continue
        try:
            print(f"{key} => {crypto.cryptojs_decrypt(blob, tok)}")
        except Exception as ex:
            print(f"{key}: 解密失败 {type(ex).__name__}: {ex}")
    rid = ca.headers.get("x-requested-id")
    if rid:
        try:
            print(f"ca.header.x-requested-id => "
                  f"{crypto.cryptojs_decrypt(rid, crypto.requested_id_key(tok))}")
        except Exception as ex:
            print(f"ca.header.x-requested-id: 解密失败 {type(ex).__name__}")
    return 0


def cmd_capture(a) -> int:
    from .capture import capture as do_capture
    obj = do_capture(a.url, a.out, headless=not a.headful, timeout_ms=a.timeout_ms,
                     user_data_dir=a.profile, proxy=a.proxy, interactive=a.interactive)
    print(f"[arp] {len(obj['requests'])} 个 Arkose 请求, 指纹明文="
          f"{'有' if obj['fp'] else '无'} -> {a.out}")
    return 0


def cmd_pool(a) -> int:
    pool = fp_pool.FingerprintPool.load(a.pool)
    print(f"[arp] 载入 {len(pool)} 条指纹")
    if a.reseal:
        pool = pool.reseal()
        print("[arp] 已重算 f/n 自洽")
    if a.clean:
        before = len(pool)
        pool = pool.clean()
        print(f"[arp] 去掉不自洽 {before - len(pool)} 条 -> {len(pool)}")
    if a.validate or a.clean:
        bad = [(i, fs) for i, fs in pool.validate_all(a.limit) if fs]
        print(f"[arp] 校验: {len(bad)} 条有问题")
        for i, fs in bad[:10]:
            print(f"   {i}: " + "; ".join(f"{f.level}/{f.code}" for f in fs))
    if a.out:
        pool.save(a.out)
        print(f"[arp] 写出 -> {a.out}")
    return 0


def _load_fp(path: str) -> dict:
    obj = json.loads(Path(path).read_text(encoding="utf-8"))
    return obj["fp"] if isinstance(obj, dict) and isinstance(obj.get("fp"), dict) else obj


def _seed_from_golden(path: str) -> generate.SessionSeed:
    cap = loaders.load(path, name="golden")
    gt2, gfct = cap.by_stage("gt2"), cap.by_stage("gfct")
    resp = (gt2.resp_json if gt2 and isinstance(gt2.resp_json, dict) else {}) or {}
    pk = (gt2.query.get("public_key") if gt2 else "") or cap.meta.get("public_key", "")
    site = (gt2.body.get("site") if gt2 else "") or ""
    seed = generate.session_from_gt2(pk, site, resp)
    if cap.session_token:
        seed.token_full = cap.session_token
    if gfct:
        generate.apply_gfct(seed, gfct.resp_json or {})
        seed.sid = seed.sid or gfct.body.get("sid", "")
    seed.blob = (gt2.body.get("data[blob]") if gt2 else None) or seed.blob
    return seed


def cmd_gen(a) -> int:
    fp = _load_fp(a.fp)
    if a.pem:
        pem = Path(a.pem).read_text(encoding="utf-8")
    else:
        pem = keys_mod.get_public_key_pem(a.public_key)
    if a.golden:
        seed = _seed_from_golden(a.golden)
    else:
        resp = json.loads(Path(a.gt2_resp).read_text(encoding="utf-8")) if a.gt2_resp else {}
        seed = generate.session_from_gt2(a.public_key, a.site, resp)
    if a.sid:
        seed.sid = a.sid
    if a.game_token:
        seed.game_token = a.game_token
    if a.site:
        seed.site = a.site
    rounds = [[int(x) for x in r.replace(" ", "").split(",") if x != ""]
              for r in (a.answers or ["0"])]
    obj = generate.build_mine(
        seed, fp, pem, rounds=rounds, ua=a.ua or generate.UA_DEFAULT,
        tguess_plain=a.tguess, requested_id_plain=a.requested_id)
    generate.write(a.out, obj)
    print(f"[arp] 生成 mine: {len(obj['requests'])} 个请求 -> {a.out}")
    return 0


def cmd_mine(a) -> int:
    from .client import ArkoseClient
    from .solver import (FixedAnswers, ManualAnswers, ScriptAnswers,
                         YesCaptchaAnswers, YesCaptchaSolver)
    fp = _load_fp(a.fp)
    pem = Path(a.pem).read_text(encoding="utf-8") if a.pem \
        else keys_mod.get_public_key_pem(a.public_key)
    if a.solver == "manual":
        provider = ManualAnswers()
    elif a.solver == "script":
        provider = ScriptAnswers(a.answers_file)
    elif a.solver == "yescaptcha":
        provider = YesCaptchaAnswers(YesCaptchaSolver(a.client_key))
    else:
        rounds = [[int(x) for x in r.replace(" ", "").split(",") if x != ""]
                  for r in (a.answers or ["0"])]
        provider = FixedAnswers(rounds=rounds)
    cli = ArkoseClient(a.public_key, a.site, ua=a.ua or generate.UA_DEFAULT,
                       proxy=a.proxy)
    res = cli.run(fp, pem, provider, tguess_plain=a.tguess,
                  requested_id_plain=a.requested_id)
    generate.write(a.out, res.obj)
    print(f"[arp] solved={res.solved} denied={res.denied} rounds={len(res.rounds)} -> {a.out}")
    return 0 if res.solved else 1


def cmd_catalog(a) -> int:
    print("# 请求参数目录（stage.where.name : category）")
    for s in CATALOG:
        print(f"  {s.stage}.{s.where}.{s.name:28} {s.category:8} {s.note}")
    print(f"\n# 39 项自检清单（{len(REQUEST_39)} 条）")
    for k in REQUEST_39:
        print(f"  {k}")
    return 0


def cmd_shape_c(a) -> int:
    print(json.dumps(crypto.split_arkose_c(a.c), ensure_ascii=False, indent=2))
    return 0


def cmd_solve(a) -> int:
    from . import pure
    if not pure.available():
        print("需要先装: python -m pip install arkose-solver", file=sys.stderr)
        return 2
    res = pure.solve(surl=a.surl, public_key=a.pk, site=a.site,
                     proxy=a.proxy, user_agent=a.ua,
                     language=a.lang, capi_mode=a.mode)
    print(f"suppressed: {res['suppressed']}")
    print(f"token: {res['token'][:150]}")
    print(f"timings: {res['timings']}")
    if a.out:
        pure.token_to_capture(res["token"], surl=a.surl, public_key=a.pk,
                              site=a.site or "", path=a.out)
        print(f"[arp] -> {a.out}")
    return 0 if res["suppressed"] else 1


def cmd_ca(a) -> int:
    """图片题（match-game）提交格式：生成 / 对账 / 解码。"""
    from . import challenge
    if a.action == "build":
        body = challenge.build_ca_body(
            session_token=a.session_token, response=a.response, language=a.lang,
            r=a.r or "", analytics_tier=a.tier,
            height=a.height, width=a.width, include_empty=a.all_fields)
        print(body)
        if a.out:
            Path(a.out).write_text(body, encoding="utf-8")
            print(f"[arp] -> {a.out}")
        return 0
    if a.action == "compare":
        g = Path(a.golden).read_text(encoding="utf-8").strip()
        m = Path(a.mine).read_text(encoding="utf-8").strip()
        rows = challenge.compare_ca(g, m)
        for r in rows:
            mark = "=" if r["status"] == "SAME" else "!"
            print(f"  {mark} {r['status']:8} {r['field']}")
            if r["status"] != "SAME":
                print(f"      golden: {str(r['golden'])[:110]}")
                print(f"      mine  : {str(r['mine'])[:110]}")
        bad = [r for r in rows if r["status"] != "SAME"]
        print(f"\n  {len(rows)-len(bad)}/{len(rows)} 字段一致" +
              ("  ✅ 对齐" if not bad else f"  ❌ {len(bad)} 处不一致"))
        return 0 if not bad else 1
    if a.action == "decode":
        body = a.body or Path(a.golden).read_text(encoding="utf-8").strip()
        f = challenge.parse_body(body)
        for k, v in f.items():
            if k in ("bio", "ecdata"):
                try:
                    dec = challenge.decode_bio(v) if k == "bio" else challenge.decode_ecdata(v)
                    print(f"  {k}: {json.dumps(dec, ensure_ascii=False)[:160]}")
                    continue
                except Exception:
                    pass
            print(f"  {k}: {str(v)[:160]}")
        return 0
    return 2


def cmd_game(a) -> int:
    """纯协议跑图片题：settings→gt2→gfct→ca（可选随机答案验证假设）。"""
    from .matchgame import MatchGame
    from .solver import FixedAnswers
    fp = _load_fp(a.fp)
    pem = Path(a.pem).read_text(encoding="utf-8") if a.pem \
        else keys_mod.get_public_key_pem(a.pk)
    mg = MatchGame(a.pk, a.site, surl=a.surl,
                   ua=a.ua or generate.UA_DEFAULT, proxy=a.proxy)
    provider = None
    response = None
    if a.response:
        response = [int(x) for x in a.response.replace(" ", "").split(",") if x != ""]
    elif not a.random:
        provider = FixedAnswers(rounds=[[int(x) for x in r.split(",")] for r in (a.answers or ["0"])])
    res = mg.run(fp, pem, provider, response=response,
                 random_response=a.random, do_ekey=a.ekey, max_rounds=a.rounds)
    st = res["state"]
    print(f"session_token : {st.session_token}")
    print(f"sid           : {st.sid}")
    print(f"challengeID   : {st.challenge_id}")
    print(f"challengeURL  : {st.challenge_url[:90]}")
    print(f"images        : {len(st.images)}")
    print(f"answered      : {res['answered']}   solved: {res['solved']}   denied: {res['denied']}")
    print(f"last -> {json.dumps(res['last'], ensure_ascii=False)[:220]}")
    if a.out:
        Path(a.out).write_text(json.dumps({
            "public_key": a.pk, "site": a.site, "surl": a.surl,
            "session_token": st.session_token, "sid": st.sid,
            "challenge_id": st.challenge_id, "challenge_url": st.challenge_url,
            "images": st.images, "game_data": st.game_data,
            "answered": res["answered"], "solved": res["solved"],
            "denied": res["denied"], "last": res["last"],
            "log": mg.log,
        }, ensure_ascii=False, indent=1), encoding="utf-8")
        print(f"[arp] -> {a.out}")
    return 0 if (res["solved"] or res["answered"]) else 1


def cmd_pow(a) -> int:
    """从 /pows/setup 的 JSON 算出 /pows/check 载荷（纯 Python，无第三方）。"""
    from . import pow as powmod
    setup = json.loads(Path(a.setup).read_text(encoding="utf-8"))
    if a.session_token:
        setup["session_token"] = a.session_token
    comp = powmod.run_pow(setup, span=a.span, parallel=not a.serial)
    payload = powmod.check_payload(setup, comp, setup.get("session_token", ""))
    print(f"hashRate={comp['hashRate']:.0f} time={comp['time']}ms "
          f"nonces={[x['iterations'] for x in comp['targetHashData']]}")
    print("transform len:", len(comp["finalTransform"]))
    if a.out:
        Path(a.out).write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        print(f"[arp] -> {a.out}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser("arp", description="Arkose FunCaptcha 三来源对齐沙箱")
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("compare", help="golden/solver/mine 逐字段对齐")
    c.add_argument("--golden", help="对方要校验的（真浏览器通过的那次）")
    c.add_argument("--solver", help="打码服务结果/回显")
    c.add_argument("--mine", help="我方沙箱生成结果")
    c.add_argument("--kind", choices=["auto", "har", "simple", "form", "netlog"], default=None)
    c.add_argument("--format", choices=["text", "json", "md", "html"], default="text")
    c.add_argument("--out", help="报告输出文件")
    c.set_defaults(func=cmd_compare)

    v = sub.add_parser("validate", help="单来源自检（对方会校验的东西）")
    v.add_argument("--capture", required=True)
    v.add_argument("--fp", help="设备指纹明文 json")
    v.add_argument("--kind", choices=["auto", "har", "simple", "form", "netlog"], default=None)
    v.set_defaults(func=cmd_validate)

    d = sub.add_parser("decrypt", help="用 session token 解密 ca 的加密参数")
    d.add_argument("--capture", required=True)
    d.add_argument("--token")
    d.add_argument("--field", help="如 ca.body.tguess")
    d.add_argument("--kind", choices=["auto", "har", "simple", "form", "netlog"], default=None)
    d.set_defaults(func=cmd_decrypt)

    sub.add_parser("catalog", help="打印参数目录/39 项清单").set_defaults(func=cmd_catalog)

    cap = sub.add_parser("capture", help="真浏览器采 golden（含指纹明文）")
    cap.add_argument("--url", required=True)
    cap.add_argument("--out", default="golden.json")
    cap.add_argument("--headful", action="store_true")
    cap.add_argument("--interactive", action="store_true")
    cap.add_argument("--profile")
    cap.add_argument("--proxy")
    cap.add_argument("--timeout-ms", type=int, default=120000)
    cap.set_defaults(func=cmd_capture)

    pl = sub.add_parser("pool", help="指纹池载入/校验/清洗")
    pl.add_argument("--pool", required=True)
    pl.add_argument("--validate", action="store_true")
    pl.add_argument("--clean", action="store_true")
    pl.add_argument("--reseal", action="store_true")
    pl.add_argument("--limit", type=int)
    pl.add_argument("--out")
    pl.set_defaults(func=cmd_pool)

    g = sub.add_parser("gen", help="离线拼 mine（复用已有会话）")
    g.add_argument("--public-key", required=True)
    g.add_argument("--fp", required=True)
    g.add_argument("--site", default="")
    g.add_argument("--pem", help="RSA 公钥 PEM；不给则联网取 api.js")
    g.add_argument("--golden", help="从 golden.exe 复用 token/sid/game_token/blob")
    g.add_argument("--gt2-resp", help="gt2 响应 json（无 golden 时用）")
    g.add_argument("--sid")
    g.add_argument("--game-token")
    g.add_argument("--answers", action="append", help="每轮下标，如 0,2；可多次")
    g.add_argument("--tguess", default='{"sc":[376,345],"st":1}')
    g.add_argument("--requested-id", default='{"sc":[376,345]}')
    g.add_argument("--ua")
    g.add_argument("--out", default="mine.json")
    g.set_defaults(func=cmd_gen)

    m = sub.add_parser("mine", help="纯协议跑 gt2/gfct/ca（联网）")
    m.add_argument("--public-key", required=True)
    m.add_argument("--site", required=True)
    m.add_argument("--fp", required=True)
    m.add_argument("--pem")
    m.add_argument("--solver", choices=["fixed", "manual", "script", "yescaptcha"],
                   default="manual")
    m.add_argument("--answers", action="append")
    m.add_argument("--answers-file")
    m.add_argument("--client-key")
    m.add_argument("--proxy")
    m.add_argument("--ua")
    m.add_argument("--tguess", default='{"sc":[376,345],"st":1}')
    m.add_argument("--requested-id", default='{"sc":[376,345]}')
    m.add_argument("--out", default="mine.json")
    m.set_defaults(func=cmd_mine)

    s = sub.add_parser("shape-c", help="切分 c 密文结构")
    s.add_argument("--c", required=True)
    s.set_defaults(func=cmd_shape_c)

    so = sub.add_parser("solve", help="纯协议出票（arkose-solver，无浏览器）")
    so.add_argument("--surl", required=True, help="Arkose verify host，如 https://arks-client.adobe.com")
    so.add_argument("--pk", required=True, help="public_key / site key")
    so.add_argument("--site", help="widget 所在 origin")
    so.add_argument("--proxy")
    so.add_argument("--ua")
    so.add_argument("--lang", default="en-US")
    so.add_argument("--mode", default="lightbox", choices=["lightbox", "inline"])
    so.add_argument("--out", help="存档为 simple 格式 json")
    so.set_defaults(func=cmd_solve)

    ca = sub.add_parser("ca", help="图片题提交格式：build/compare/decode")
    casub = ca.add_subparsers(dest="action", required=True)
    cb = casub.add_parser("build", help="生成 POST /fc/ca/ 的 form-urlencoded body")
    cb.add_argument("--session-token", required=True)
    cb.add_argument("--response", required=True, help="答案，如 0,2")
    cb.add_argument("--lang", default="en")
    cb.add_argument("--r", default="")
    cb.add_argument("--tier", type=int, default=40)
    cb.add_argument("--height", type=int, default=400)
    cb.add_argument("--width", type=int, default=400)
    cb.add_argument("--all-fields", action="store_true", help="保留空字段便于对账")
    cb.add_argument("--out")
    cb.set_defaults(func=cmd_ca)
    cc = casub.add_parser("compare", help="golden vs mine 逐字段对账")
    cc.add_argument("--golden", required=True)
    cc.add_argument("--mine", required=True)
    cc.set_defaults(func=cmd_ca)
    cd = casub.add_parser("decode", help="解码 body（bio/ecdata 自动解 base64）")
    cd.add_argument("--body")
    cd.add_argument("--golden")
    cd.set_defaults(func=cmd_ca)

    gm = sub.add_parser("game", help="纯协议图片题：settings→gt2→gfct→ca")
    gm.add_argument("--pk", required=True, help="Arkose public_key")
    gm.add_argument("--site", default="https://auth.services.adobe.com")
    gm.add_argument("--surl", default="arks-client.adobe.com")
    gm.add_argument("--fp", default="examples/fp.json")
    gm.add_argument("--pem")
    gm.add_argument("--ua")
    gm.add_argument("--proxy")
    gm.add_argument("--response", help="固定答案，如 0,2")
    gm.add_argument("--answers", action="append", help="按轮给答案（可重复）")
    gm.add_argument("--random", action="store_true", help="随机 response（验证只校验信封）")
    gm.add_argument("--ekey", action="store_true", help="额外取解密密钥")
    gm.add_argument("--rounds", type=int, default=8)
    gm.add_argument("--out", default="data/game.json")
    gm.set_defaults(func=cmd_game)

    pw = sub.add_parser("pow", help="纯 Python 复现 PoW（setup -> check 载荷）")
    pw.add_argument("--setup", required=True, help="/pows/setup 的 JSON")
    pw.add_argument("--session-token", default="")
    pw.add_argument("--span", type=int, default=200_000_000, help="并行搜索跨度")
    pw.add_argument("--serial", action="store_true", help="单进程（调参用）")
    pw.add_argument("--out")
    pw.set_defaults(func=cmd_pow)
    orc = sub.add_parser("oracle", help="指纹预言机：用真浏览器的 c 跑纯协议链路")
    orc.add_argument("--pk", required=True, help="Arkose public_key")
    orc.add_argument("--site", default="https://auth.services.adobe.com")
    orc.add_argument("--surl", default="arks-client.adobe.com")
    orc.add_argument("--c", help="浏览器 gt2 的 c 字段（bda 密文）")
    orc.add_argument("--c-file", default="data/browser_gt2.json",
                     help="从 JSON 文件读 c / userbrowser")
    orc.add_argument("--save", default="data/browser_gt2.json",
                     help="现场抓取时缓存到这个文件")
    orc.add_argument("--no-capture", action="store_true",
                     help="不许现场开浏览器，只用 --c/--c-file")
    orc.add_argument("--capture", dest="no_capture", action="store_false")
    orc.set_defaults(no_capture=False)
    orc.add_argument("--channel", default="chrome", help="Playwright 频道")
    orc.add_argument("--wait", type=int, default=25000, help="抓指纹等待毫秒")
    orc.add_argument("--fp", default="data/grab_fresh.json", help="指纹 JSON（含 fe/enhanced_fp）")
    orc.add_argument("--pem", help="RSA 公钥 PEM；不给则用 --keycache")
    orc.add_argument("--keycache", default="arp/keycache/430FF2C3-1AB1-40B7-8BE7-44FC683FE02C.pem")
    orc.add_argument("--blob", help="Adobe 的 data[blob]（x-ims-captcha-encrypted）")
    orc.add_argument("--blob-file", default="data/adobe/blob.json")
    orc.add_argument("--ua")
    orc.add_argument("--capi-mode", default="inline")
    orc.add_argument("--proxy")
    orc.add_argument("--node")
    orc.add_argument("--response", type=lambda s: [int(x) for x in s.split(",")],
                     default=[0, 1, 2, 3, 4], help="要试的答案下标，如 0,1,2")
    orc.add_argument("--sc-x", type=int, default=199)
    orc.add_argument("--sc-y", type=int, default=233)
    orc.add_argument("--out", default="data/oracle.json")
    orc.set_defaults(func=cmd_oracle)

    return p


def cmd_oracle(args) -> int:
    """指纹预言机：拿**真浏览器现算的 `c`** 当指纹，跑纯协议链路。

    `c`（gt2 的第 9 个字段，`bda` 密文）由真浏览器/真 VM 算出，与 RSA 公钥绑定、
    不绑会话，所以可以缓存复用。这样纯协议请求的指纹就与真浏览器**逐字节相同**。

    来源优先级: --c > --c-file > （默认）现场开 Playwright 抓
    """
    import json as _json
    import os as _os
    import time as _t
    from .matchgame import MatchGame

    src = args.c
    if not src and args.c_file and _os.path.exists(args.c_file):
        d = _json.load(open(args.c_file, encoding="utf-8"))
        src = d.get("c") if isinstance(d, dict) else None
        if src and not args.ua:
            args.ua = d.get("userbrowser")
    if not src and not args.no_capture:
        from playwright.sync_api import sync_playwright
        from urllib.parse import parse_qsl
        br = {}
        with sync_playwright() as p:
            b = p.chromium.launch(headless=True, channel=args.channel)
            ctx = b.new_context(locale="en-US")
            pg = ctx.new_page()
            def _onr(r):
                if "/fc/gt2/" in r.url:
                    try:
                        br.update(dict(parse_qsl(r.request.post_data)))
                    except Exception:
                        pass
            ctx.on("response", _onr)
            pg.goto(f"https://iframe.arkoselabs.com/{args.pk}/index.html",
                    wait_until="domcontentloaded", timeout=90000)
            pg.wait_for_timeout(args.wait)
            b.close()
        src = br.get("c")
        args.ua = args.ua or br.get("userbrowser")
        if args.save:
            _json.dump({"c": src, "userbrowser": args.ua,
                        "capi_mode": br.get("capi_mode"),
                        "capi_version": br.get("capi_version")},
                       open(args.save, "w", encoding="utf-8"), indent=1)
            print(f"[oracle] 已缓存指纹 -> {args.save}")
    if not src:
        print("[oracle] 没拿到 c（--c/--c-file 或允许现场抓）")
        return 2
    print(f"[oracle] c 长度 = {len(src)}")

    blob = args.blob
    if not blob and args.blob_file and _os.path.exists(args.blob_file):
        blob = _json.load(open(args.blob_file, encoding="utf-8")).get("blob")
    pem = args.pem or open(args.keycache, encoding="utf-8").read()
    fp = _json.load(open(args.fp, encoding="utf-8"))
    if isinstance(fp, list):
        fp = fp[0]["fp"]

    mg = MatchGame(args.pk, args.site, surl=args.surl, node=args.node,
                   ua=args.ua or None, capi_mode=args.capi_mode,
                   fp_override=src, blob=blob, proxy=args.proxy)
    s = mg.session()
    st = mg.gt2(s, fp, pem)
    print(f"[oracle] gt2 ok  session={st.session_token}")
    if not mg.pows(s, st):
        print("[oracle] pows 失败")
        return 3
    mg.gfct(s, st)
    mg.dapib(s, st)
    print(f"[oracle] gfct ok  challengeID={st.challenge_id}  dapib={len(st.dapib_src)}B")
    out = {"session_token": st.session_token, "challenge_id": st.challenge_id,
           "blob": blob, "rounds": []}
    for n in args.response:
        tg = mg.tguess_for(st, [{"index": n}])
        r = mg.ca(s, st, n, tguess=tg, sc=(args.sc_x, args.sc_y))
        j = r.get("resp_json") or {}
        rec = {"index": n, "status": r["status"], "resp": j}
        out["rounds"].append(rec)
        print(f"[oracle] ca index={n} -> {r['status']} "
              f"response={j.get('response')} solved={j.get('solved')} "
              f"incorrect_guess={j.get('incorrect_guess')}")
        if j.get("response") == "answered":
            print("[oracle] ✅ 服务端进入判题阶段！")
            break
        _t.sleep(0.3)
    if args.out:
        _json.dump(out, open(args.out, "w", encoding="utf-8"), indent=1)
        print(f"[oracle] -> {args.out}")
    return 0


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if getattr(args, "kind", None) == "auto":
        args.kind = None
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
