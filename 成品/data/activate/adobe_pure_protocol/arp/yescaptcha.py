"""YesCaptcha 客户端：FunCaptchaClassification（Arkose match-game 分类）。"""
import base64, json, time, sys

API = "https://api.yescaptcha.com"

# ★ 连接复用：TLS 握手 ~0.3s/次，每轮 2 次调用 ⇒ 免费省 ~0.6s/轮
_SESS = None


def _sess():
    global _SESS
    if _SESS is None:
        from curl_cffi import requests as cr
        _SESS = cr.Session(impersonate="chrome")
    return _SESS


def _post(path, body, timeout=40, retries=4):
    last = None
    for i in range(retries):
        try:
            try:
                r = _sess().post(API + path, json=body, timeout=timeout)
                if r.status_code >= 500:
                    raise RuntimeError("http %s" % r.status_code)
            except Exception:
                global _SESS
                _SESS = None
                import requests
                r = requests.post(API + path, json=body, timeout=timeout)
            try:
                return r.json()
            except Exception:
                return {"_status": getattr(r, "status_code", None), "_text": getattr(r, "text", "")[:400]}
        except Exception as e:
            last = e
            time.sleep(1.5 * (i + 1))
    return {"errorId": -2, "errorDescription": "network: %s" % (last,)}

# firefly-go 开发者 softID：用户消费 20% 计入分成
SOFT_ID = 136300

def create(client_key, image_b64, question, ttype="FunCaptchaClassification"):
    return _post("/createTask", {"clientKey": client_key,
                                 "softID": SOFT_ID,
                                 "task": {"type": ttype, "image": image_b64, "question": question}})

def get_result(client_key, task_id):
    return _post("/getTaskResult", {"clientKey": client_key, "taskId": task_id})

def balance(client_key):
    return _post("/getBalance", {"clientKey": client_key})

def classify(client_key, image_path, question, timeout=150, ttype="FunCaptchaClassification",
             interval=0.2):
    """★ interval 原来 1.0 且【先 sleep 再轮询】⇒ 每轮白扔 1s。改成 0.2 + 立即轮询。"""
    b64 = base64.b64encode(open(image_path, "rb").read()).decode()
    j = create(client_key, b64, question, ttype)
    if j.get("errorId"):
        return j
    tid = j.get("taskId")
    t0 = time.time()
    while time.time() - t0 < timeout:
        j = get_result(client_key, tid)
        if j.get("status") == "ready":
            return j
        if j.get("errorId"):
            return j
        time.sleep(interval)
    return {"errorId": -1, "errorDescription": "timeout", "taskId": tid}

if __name__ == "__main__":
    KEY = sys.argv[1]
    IMG = sys.argv[2] if len(sys.argv) > 2 else "data/img/chal0.png"
    Q = sys.argv[3] if len(sys.argv) > 3 else "icon_constellation"
    print("balance:", balance(KEY))
    print("classify(question=%r):" % Q, json.dumps(classify(KEY, IMG, Q), ensure_ascii=False)[:600])
