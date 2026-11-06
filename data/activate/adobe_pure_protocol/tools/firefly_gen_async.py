"""Firefly 异步生图（可用链路）：submit → 轮询 result → 下载。
   1P: POST https://firefly-clio-imaging.adobe.io/v2/images/generate-async
   轮询: GET  {links.result.href}  (https://firefly-epo*.adobe.io/jobs/result/<job>)

用法:
  python tools/firefly_gen_async.py --token data/adobe/e2e_bonnie.json \
         --prompt "..." --w 1024 --h 1024 --model firefly-image --ver image5 \
         --out data/firefly/async.png
"""
import sys, os, json, time, argparse, hashlib, base64
sys.path.insert(0, ".")
from curl_cffi import requests as cr

ap = argparse.ArgumentParser()
ap.add_argument("--token", default="data/adobe/e2e_bonnie.json")
ap.add_argument("--prompt", default="a copper teapot on a wooden table, warm light")
ap.add_argument("--w", type=int, default=1024)
ap.add_argument("--h", type=int, default=1024)
ap.add_argument("--model", default="firefly-image")
ap.add_argument("--ver", default="image5")
ap.add_argument("--seed", type=int, default=0)
ap.add_argument("--cid", default="clio-playground-web")
ap.add_argument("--host", default="https://firefly-clio-imaging.adobe.io")
ap.add_argument("--path", default="/v2/images/generate-async")
ap.add_argument("--out", default="data/firefly/async.png")
ap.add_argument("--timeout", type=int, default=180)
a = ap.parse_args()

j = json.load(open(a.token, encoding="utf-8"))
AT = j["tokens"]["access_token"] if "tokens" in j else j["access_token"]
p = AT.split(".")[1]; p += "=" * (-len(p) % 4)
uid = json.loads(base64.urlsafe_b64decode(p))["user_id"]
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36")
H = {"content-type": "application/json", "x-api-key": a.cid,
     "authorization": "Bearer " + AT, "user-agent": UA,
     "accept": "application/json, text/plain, */*",
     "origin": "https://firefly.adobe.com", "referer": "https://firefly.adobe.com/",
     "x-nonce": hashlib.sha256((uid + "-" + a.prompt[:256]).encode()).hexdigest()}
B = {"n": 1, "prompt": a.prompt, "size": {"width": a.w, "height": a.h},
     "referenceBlobs": [], "caiClaimVersion": 2, "modelSpecificPayload": {},
     "modelId": a.model, "modelVersion": a.ver,
     "generationMetadata": {"module": "text2image", "submodule": "ff-image-generate"}}
if a.seed:
    B["seeds"] = [a.seed]

os.makedirs(os.path.dirname(a.out), exist_ok=True)
print(f"submit {a.host}{a.path}  {a.w}x{a.h}  {a.model}/{a.ver}")
r = cr.post(a.host + a.path, headers=H, data=json.dumps(B), impersonate="chrome", timeout=120)
print(f"  -> {r.status_code}")
if r.status_code != 200:
    print("  ", r.text[:300]); sys.exit(1)
res = r.json()
url = ((res.get("links") or {}).get("result") or {}).get("href")
print("  result url:", url)
if not url:
    print("  ", json.dumps(res)[:300]); sys.exit(1)

t0 = time.time()
while time.time() - t0 < a.timeout:
    rr = cr.get(url, headers=H, impersonate="chrome", timeout=60)
    if rr.status_code != 200:
        print("  poll", rr.status_code, rr.text[:120]); time.sleep(4); continue
    d = rr.json()
    outs = d.get("outputs") or []
    if outs:
        u = (outs[0].get("image") or {}).get("presignedUrl")
        raw = cr.get(u, impersonate="chrome", timeout=180).content
        open(a.out, "wb").write(raw)
        print(f"  ★ 出图 {len(raw)}B  seed={outs[0].get('seed')} -> {a.out}")
        json.dump(d, open(a.out.rsplit('.', 1)[0] + ".json", "w"), ensure_ascii=False, indent=1)
        break
    if d.get("error_code") or d.get("error"):
        print("  ERROR:", json.dumps(d, ensure_ascii=False)[:300]); break
    time.sleep(3)
else:
    print("  超时")
