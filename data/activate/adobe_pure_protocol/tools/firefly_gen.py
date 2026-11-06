"""Firefly 生图（纯协议）：POST /v2/images/generate → 下载图片。
用法: python tools/firefly_gen.py --prompt "..." [--model <id>] [--w 1024 --h 1024] [--out x.png]
"""
import sys, os, json, argparse, time
sys.path.insert(0, ".")
from curl_cffi import requests as cr

ap = argparse.ArgumentParser()
ap.add_argument("--prompt", default="a serene Japanese garden with cherry blossoms, photorealistic")
ap.add_argument("--model", default=None)
ap.add_argument("--w", type=int, default=1024)
ap.add_argument("--h", type=int, default=1024)
ap.add_argument("--n", type=int, default=1)
ap.add_argument("--seed", type=int, default=0)
ap.add_argument("--out", default="data/firefly/out.png")
ap.add_argument("--try-models", action="store_true")
a = ap.parse_args()

j = json.load(open("data/adobe/CREDS.json", encoding="utf-8"))
AT = j["access_token"]
CID = "clio-playground-web"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36")
os.makedirs(os.path.dirname(a.out), exist_ok=True)
API = "https://firefly.adobe.io/v2/images/generate"
H = {"authorization": "Bearer " + AT, "x-api-key": CID, "user-agent": UA,
     "accept": "application/json, text/plain, */*",
     "origin": "https://firefly.adobe.com", "referer": "https://firefly.adobe.com/",
     "content-type": "application/json;charset=UTF-8"}

CAND = ["gpt-image_gpt-image-2.5-flare", "gpt-image_gpt-image-2.5-prism",
        "firefly-image-gpt-image-25-flare-model", "firefly-image-gpt-image-2-model",
        "gpt-image2", "gpt-image_2", "firefly-image-gpt-image-15-model",
        "firefly-image3", "firefly-image4", "gemini-flash_nano-banana-2",
        "flux2-pro", "firefly-image-gpt-4o-model"]

if a.try_models:
    print("=== 试 modelId ===")
    for m in CAND:
        body = {"prompt": "a red cube", "n": 1, "size": {"width": 512, "height": 512},
                "modelId": m}
        try:
            r = cr.post(API, headers=H, data=json.dumps(body), impersonate="chrome", timeout=90)
            ok = r.status_code
            note = ""
            if ok == 200:
                try:
                    o = r.json()["outputs"][0]
                    note = f"image id={o['image']['id']} size={r.json().get('size')}"
                except Exception:
                    note = r.text[:120]
            else:
                note = r.text[:130].replace("\n", " ")
            print(f"  {m:38s} -> {ok} {note}")
        except Exception as e:
            print(f"  {m:38s} EXC {str(e)[:70]}")
    sys.exit(0)


def gen(model=None, prompt=None, w=None, h=None, seed=None):
    body = {"prompt": prompt or a.prompt, "n": a.n,
            "size": {"width": w or a.w, "height": h or a.h}}
    if model:
        body["modelId"] = model
    if seed:
        body["seeds"] = [seed]
    r = cr.post(API, headers=H, data=json.dumps(body), impersonate="chrome", timeout=180)
    return r


t0 = time.time()
r = gen(a.model, seed=a.seed or None)
print(f"POST -> {r.status_code}  ({time.time()-t0:.1f}s)")
if r.status_code != 200:
    print(r.text[:500]); sys.exit(1)
res = r.json()
print("version", res.get("version"), "size", res.get("size"), "outputs", len(res.get("outputs") or []))
paths = []
for i, o in enumerate(res.get("outputs") or []):
    url = (o.get("image") or {}).get("presignedUrl")
    if not url:
        continue
    img = cr.get(url, impersonate="chrome", timeout=180).content
    p = a.out if len(res["outputs"]) == 1 else a.out.replace(".png", f"_{i}.png")
    open(p, "wb").write(img)
    print(f"  [{i}] seed={o.get('seed')} {len(img)}B -> {p}")
    paths.append(p)
json.dump({"prompt": a.prompt, "model": a.model, "result": res, "files": paths},
          open(a.out.replace(".png", ".json"), "w"), ensure_ascii=False, indent=1)
print("files:", paths)
