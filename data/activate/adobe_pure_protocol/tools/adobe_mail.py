"""Adobe 注册用的邮箱：从 Outlook 池取号 + 等 Adobe 邮件（验证码/链接）。

账号文件格式（E:\\typesafe\\email.txt，每行一条）：
    email----password----<client_id|refresh_token>----<refresh_token|client_id>
（哪段更长哪段就是 refresh_token）

用法：
    python tools/adobe_mail.py --pick                     # 取一个可用邮箱
    python tools/adobe_mail.py --pick --wait 600          # 取号并等 Adobe 邮件
    python tools/adobe_mail.py --email x@outlook.com --wait 600
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

ROOT = os.environ.get("ADOBE_MAIL_ROOT") or r"E:\typesafe"   # ★ 可用环境变量覆盖
ACCOUNTS = os.path.join(ROOT, "email.txt")
USED = os.path.join(ROOT, "key-email.txt")
STATE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "data", "adobe", "mail_state.json")


def parse_line(line: str):
    parts = [p.strip() for p in line.split("----") if p.strip()]
    if len(parts) < 4:
        return None
    email, password = parts[0], parts[1]
    a, b = parts[2], parts[3]
    client_id, refresh = (a, b) if len(a) < len(b) else (b, a)
    return {"email": email, "password": password,
            "client_id": client_id, "refresh": refresh}


def load_accounts():
    out = []
    for fn in ("email.txt", "new.txt", "new1.txt"):
        p = os.path.join(ROOT, fn)
        if not os.path.exists(p):
            continue
        for ln in open(p, encoding="utf-8", errors="replace"):
            a = parse_line(ln)
            if a:
                out.append(a)
    return out


def pick_account(offset: int = 0):
    """挑一个还没被用过的（不在 key-email.txt 里），支持 offset 跳过。"""
    used = set()
    if os.path.exists(USED):
        for ln in open(USED, encoding="utf-8", errors="replace"):
            e = ln.split("----")[0].strip().lower()
            if e:
                used.add(e)
    accs = load_accounts()
    fresh = [a for a in accs if a["email"].lower() not in used]
    pool = fresh or accs
    return pool[offset % len(pool)], len(fresh), len(accs)


def refresh_access(client_id: str, refresh: str, retries: int = 3) -> str:
    form = urllib.parse.urlencode({
        "client_id": client_id, "grant_type": "refresh_token",
        "refresh_token": refresh}).encode()
    req = urllib.request.Request(
        "https://login.microsoftonline.com/consumers/oauth2/v2.0/token",
        data=form, method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"})
    err = None
    for i in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.loads(r.read().decode())["access_token"]
        except Exception as e:
            err = e
            time.sleep(1.5 * (i + 1))
    raise RuntimeError(f"refresh_access failed: {err}")


def outlook(access: str, path: str):
    req = urllib.request.Request(
        "https://outlook.office.com/api/v2.0" + path,
        headers={"Authorization": "Bearer " + access, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode())


ADOBE_HINT = ("adobe", "message.adobe", "mail.adobe", "adobesign", "account.adobe")


def is_adobe(subj: str, preview: str, frm: str) -> bool:
    s = f"{subj} {preview} {frm}".lower()
    return any(h in s for h in ADOBE_HINT)


def extract(text: str):
    """从邮件正文提取验证码/链接。"""
    code = None
    m = re.search(r"\b(\d{6})\b", text)
    if m:
        code = m.group(1)
    m2 = re.search(r"https?://[^\s\"'<>)]*(?:adobe|adobesign)[^\s\"'<>)]*", text)
    link = m2.group(0) if m2 else None
    return code, link


def wait_adobe(access: str, since_iso: str, *, timeout: int = 600,
               poll: float = 5.0, want: str = ""):
    """等 Adobe 邮件。want 非空时只回含该子串的邮件。"""
    deadline = time.time() + timeout
    seen = set()
    while time.time() < deadline:
        for folder in ("inbox", "junkemail"):
            try:
                data = outlook(
                    access,
                    f"/me/mailfolders/{folder}/messages?$top=10"
                    "&$select=Subject,From,ReceivedDateTime,BodyPreview,Body"
                    "&$orderby=ReceivedDateTime%20desc")
            except Exception as e:
                print(f"  [{folder}] 读取失败: {str(e)[:80]}")
                continue
            for msg in data.get("value") or []:
                when = msg.get("ReceivedDateTime") or ""
                if when < since_iso:
                    continue
                mid = f"{folder}:{when}:{msg.get('Subject','')}"
                if mid in seen:
                    continue
                subj = msg.get("Subject") or ""
                preview = msg.get("BodyPreview") or ""
                frm = ((msg.get("From") or {}).get("EmailAddress") or {}).get("Address") or ""
                if not is_adobe(subj, preview, frm):
                    continue
                seen.add(mid)
                content = (msg.get("Body") or {}).get("Content") or ""
                clean = re.sub(r"<[^>]+>", " ", content)
                code, link = extract(preview + " " + clean)
                rec = {"when": when, "folder": folder, "from": frm, "subject": subj,
                       "code": code, "link": link, "preview": preview[:400]}
                print("\n📧 Adobe 邮件到达！")
                print(f"   时间   : {when}")
                print(f"   发件人 : {frm}")
                print(f"   主题   : {subj}")
                print(f"   验证码 : {code}")
                print(f"   链接   : {link}")
                print(f"   摘要   : {preview[:200]}")
                if want and want.lower() not in (subj + preview).lower():
                    print(f"   (不含 '{want}'，继续等)")
                    continue
                return rec
        time.sleep(poll)
    print(f"[!] 等待 {timeout}s 超时，没有收到 Adobe 邮件")
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pick", action="store_true", help="自动挑一个未用过的邮箱")
    ap.add_argument("--offset", type=int, default=0, help="跳过前 N 个")
    ap.add_argument("--email", help="指定邮箱")
    ap.add_argument("--wait", type=int, default=0, help="等 Adobe 邮件多少秒")
    ap.add_argument("--want", default="", help="只接受含该子串的邮件")
    ap.add_argument("--since", type=int, default=120, help="只看最近 N 秒前的邮件")
    ap.add_argument("--out", default=os.path.join("data", "adobe", "account.json"))
    a = ap.parse_args()

    if a.email:
        acc = next((x for x in load_accounts()
                    if x["email"].lower() == a.email.lower()), None)
        if not acc:
            acc = {"email": a.email, "password": "", "client_id": "", "refresh": ""}
        accs = load_accounts()
        print(f"指定邮箱: {acc['email']}（池内共 {len(accs)} 个）")
    else:
        acc, nfresh, nall = pick_account(a.offset)
        print(f"挑中邮箱: {acc['email']}")
        print(f"  未用过 {nfresh} / 总共 {nall}")
    print(f"  密码: {acc['password']}")
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    json.dump(acc, open(a.out, "w", encoding="utf-8"), indent=1)
    print(f"  已存 -> {a.out}")

    if a.wait:
        print("\n[*] 刷新 Outlook access token…")
        try:
            tok = refresh_access(acc["client_id"], acc["refresh"])
            print("    token OK")
        except Exception as e:
            print(f"    token 失败: {str(e)[:120]}")
            print("    （邮箱仍可用，只是无法自动等邮件）")
            return 1
        since = (datetime.now(timezone.utc) - timedelta(seconds=a.since)
                 ).strftime("%Y-%m-%dT%H:%M:%SZ")
        print(f"[*] 开始等 Adobe 邮件（{a.wait}s，since={since}）…")
        rec = wait_adobe(tok, since, timeout=a.wait, want=a.want)
        if rec:
            json.dump(rec, open(os.path.join("data", "adobe", "adobe_mail.json"), "w",
                                encoding="utf-8"), indent=1, ensure_ascii=False)
            print("\n[+] 已存 -> data/adobe/adobe_mail.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
