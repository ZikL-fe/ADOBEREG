"""golden 采集：用真浏览器跑一次，把 gt2/gfct/ca 连同**设备指纹明文**一起录下来。

关键点：Arkose 用 WebCrypto 加密指纹（AES-GCM 包指纹 JSON，再用 RSA-OAEP 包 AES 密钥）。
所以我们**不用逆 api.js 的 case 21**，直接 hook `crypto.subtle.encrypt`，
在 AES-GCM 那一步把明文 data 抄下来即可（文章说 case 21 -> case 9 的 r 就是它）。

    python -m arp capture --url https://目标站点 --out golden.json --headful

需要 playwright（Windows 侧有）。
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import List, Optional

from .loaders import _parse_body, _parse_qs
from .model import stage_of

# 在页面脚本之前注入
HOOK_JS = r"""
(() => {
  window.__arkose_fp_raws = [];
  window.__arkose_keys = [];
  window.__arkose_algos = [];
  window.__arkose_aes = [];
  const b64 = (buf) => {
    try {
      const u = buf instanceof ArrayBuffer ? new Uint8Array(buf)
              : (ArrayBuffer.isView(buf) ? new Uint8Array(buf.buffer) : null);
      if (!u) return null;
      let s = ''; for (let i = 0; i < u.length; i++) s += String.fromCharCode(u[i]);
      return btoa(s);
    } catch (e) { return null; }
  };
  const txt = (buf) => {
    try {
      const u = buf instanceof ArrayBuffer ? new Uint8Array(buf)
              : (ArrayBuffer.isView(buf) ? new Uint8Array(buf.buffer) : null);
      return u ? new TextDecoder().decode(u) : String(buf);
    } catch (e) { return null; }
  };
  const install = () => {
    const c = window.crypto;
    if (!c || !c.subtle || c.subtle.__arp_hooked) return;
    c.subtle.__arp_hooked = true;
    const oe = c.subtle.encrypt.bind(c.subtle);
    const oi = c.subtle.importKey.bind(c.subtle);
    const og = c.subtle.generateKey.bind(c.subtle);
    c.subtle.encrypt = function (algo, key, data) {
      try {
        const n = String((algo && algo.name) || algo).toUpperCase();
        window.__arkose_algos.push(n);
        const rec = {
          name: n,
          iv: (algo && algo.iv) ? Array.from(new Uint8Array(algo.iv)) : null,
          pt: txt(data),
          key_b64: null,
        };
        window.__arkose_aes.push(rec);
        if (n.indexOf('AES') >= 0) {
          const t = txt(data);
          if (t) window.__arkose_fp_raws.push(t);
        }
        try {
          c.subtle.exportKey('raw', key).then(function (b) {
            rec.key_b64 = b64(b);
          }).catch(function () {});
        } catch (e) {}
      } catch (e) {}
      return oe(algo, key, data);
    };
    c.subtle.importKey = function (fmt, keyData, algo, ext, usages) {
      try {
        const a = String((algo && algo.name) || algo);
        const rec = { fmt: fmt, algo: a };
        if (fmt === 'spki' || fmt === 'raw') rec.b64 = b64(keyData);
        else if (fmt === 'jwk') rec.jwk = keyData;
        if ((a || '').toUpperCase().indexOf('RSA') >= 0 || fmt === 'spki')
          window.__arkose_keys.push(rec);
      } catch (e) {}
      return oi(fmt, keyData, algo, ext, usages);
    };
  };
  install();
  document.addEventListener('DOMContentLoaded', install);
  try {
    const proto = Object.getPrototypeOf(window);
    const desc = Object.getOwnPropertyDescriptor(proto, 'crypto');
    if (desc && desc.get && !desc.get.__arp_wrapped) {
      const g = desc.get;
      const ng = function () { const v = g.call(this); try { install(); } catch (e) {} return v; };
      ng.__arp_wrapped = true;
      Object.defineProperty(proto, 'crypto', { ...desc, get: ng });
    }
  } catch (e) {}
})();
"""


def rsa_pem_from_keys(keys) -> Optional[str]:
    """把 hook 到的 spki(jwk) 拼回 PEM。"""
    import base64 as _b64
    for k in reversed(keys or []):
        if k.get("b64") and ("RSA" in (k.get("algo") or "").upper() or k.get("fmt") == "spki"):
            body = "\n".join(k["b64"][i:i + 64] for i in range(0, len(k["b64"]), 64))
            return f"-----BEGIN PUBLIC KEY-----\n{body}\n-----END PUBLIC KEY-----\n"
    return None


def _collect(page, expr: str) -> list:
    """从所有 frame 汇总（crypto 常在嵌套 enforcement frame）。"""
    out: list = []
    for fr in page.frames:
        try:
            v = fr.evaluate(expr)
        except Exception:
            continue
        if isinstance(v, list):
            out += v
    return out


def _to_dict(obj):
    """Arkose 线上指纹是 [{key,value},...]，递归转成 dict。"""
    if isinstance(obj, list) and obj and isinstance(obj[0], dict) and "key" in obj[0]:
        return {e["key"]: _to_dict(e.get("value")) for e in obj}
    if isinstance(obj, list):
        return [_to_dict(x) for x in obj]
    return obj


def _extract_fp(raws: List[str]) -> Optional[dict]:
    """从 AES-CBC/GCM 明文里挑出指纹 JSON（含 api_type/fe/enhanced_fp 等）。

    线上两种形态都支持：dict，或 Arkose 的 [{key,value}] 数组。
    """
    for txt in reversed(raws or []):
        try:
            obj = json.loads(txt)
        except Exception:
            continue
        obj = _to_dict(obj)
        if isinstance(obj, dict) and any(
                k in obj for k in ("api_type", "fe", "enhanced_fp", "f", "wh")):
            return obj
    return None


def capture(url: str, out: str, *, headless: bool = True, timeout_ms: int = 120000,
            user_data_dir: Optional[str] = None, proxy: Optional[str] = None,
            settle_ms: int = 3000, interactive: bool = False) -> dict:
    from playwright.sync_api import sync_playwright

    records: List[dict] = []
    resp_map: dict = {}

    with sync_playwright() as p:
        pw_proxy = {"server": proxy} if proxy else None
        if user_data_dir:
            ctx = p.chromium.launch_persistent_context(
                user_data_dir, headless=headless, proxy=pw_proxy)
            browser = None
        else:
            browser = p.chromium.launch(headless=headless, proxy=pw_proxy)
            ctx = browser.new_context(locale="zh-CN")
        ctx.add_init_script(HOOK_JS)
        page = ctx.new_page()

        def on_request(req):
            if "arkoselabs.com/fc/" not in req.url:
                return
            st = stage_of(req.url)
            if st == "other":
                return
            try:
                hdrs = {k.lower(): v for k, v in req.headers.items()}
            except Exception:
                hdrs = {}
            records.append({
                "stage": st, "url": req.url, "headers": hdrs,
                "query": _parse_qs(req.url),
                "body": _parse_body(req.post_data or "", hdrs.get("content-type", "")),
                "raw_body": req.post_data,
                "_t": time.time(),
            })

        def on_response(resp):
            if "arkoselabs.com/fc/" not in resp.url:
                return
            try:
                txt = resp.text()
            except Exception:
                return
            try:
                obj = json.loads(txt)
            except Exception:
                obj = None
            resp_map[resp.url] = {"status": resp.status, "resp_json": obj, "resp_text": txt}

        page.on("request", on_request)
        page.on("response", on_response)

        page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
        if interactive:
            input("[arp] 请在浏览器里完成验证，完成后按回车...")
        else:
            # 等到出现 ca 请求（或在 settle 后收工）
            deadline = time.time() + timeout_ms / 1000
            while time.time() < deadline:
                if any(r["stage"] == "ca" for r in records) \
                        and time.time() - max(r["_t"] for r in records) > settle_ms / 1000:
                    break
                page.wait_for_timeout(500)
        raws = _collect(page, "window.__arkose_fp_raws || []")
        keys = _collect(page, "window.__arkose_keys || []")
        algos = _collect(page, "window.__arkose_algos || []")
        fp = _extract_fp(raws)
        pem = rsa_pem_from_keys(keys)
        if ctx and not user_data_dir:
            ctx.close()
        if browser:
            browser.close()

    for r in records:
        m = resp_map.get(r["url"])
        if m:
            r.update(m)
        r.pop("_t", None)

    obj = {
        "meta": {"generator": "arp.capture", "url": url, "captured_at": time.time(),
                 "algos": algos, "n_keys": len(keys)},
        "session_token": None,
        "fp": fp,
        "pem": pem,
        "requests": records,
    }
    Path(out).write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")
    return obj


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser("arp capture", description="真浏览器采集 golden")
    ap.add_argument("--url", required=True)
    ap.add_argument("--out", default="golden.json")
    ap.add_argument("--headful", action="store_true", help="显示浏览器窗口（默认 headless）")
    ap.add_argument("--interactive", action="store_true", help="手动完成后按回车")
    ap.add_argument("--profile", help="持久化用户目录（带 cookie/登录态）")
    ap.add_argument("--proxy", help="如 http://127.0.0.1:7890")
    ap.add_argument("--timeout-ms", type=int, default=120000)
    a = ap.parse_args(argv)
    obj = capture(a.url, a.out, headless=not a.headful, timeout_ms=a.timeout_ms,
                  user_data_dir=a.profile, proxy=a.proxy, interactive=a.interactive)
    print(f"[arp] 采集到 {len(obj['requests'])} 个 Arkose 请求，指纹明文="
          f"{'有' if obj['fp'] else '无'} -> {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
