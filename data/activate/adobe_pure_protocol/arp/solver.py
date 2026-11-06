"""打码接入（YesCaptcha / 2Captcha 风格），以及人工/固定答案的 provider。

Arkose 的题目是“每轮一张图选 N 个”，所以对接分类接口：
    POST /createTask  {"task":{"type":"FunCaptchaClassification","image":"<b64>","question":"..."}}
    POST /getTaskResult -> solution: {"objects":[0,2]}  (下标)
也支持整题出 token 的 FunCaptchaTaskProxyless（仅作参考/兜底）。
"""
from __future__ import annotations

import base64
import json
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional, Protocol, Sequence


class AnswerProvider(Protocol):
    def answers_for(self, round_index: int, challenge: dict) -> Sequence[int]:
        """返回本轮该选的图片下标，如 [0, 2]。"""


# ---------------------------------------------------------------------------
@dataclass
class FixedAnswers:
    """离线/自测用：按轮次给固定答案。"""
    rounds: List[Sequence[int]] = field(default_factory=list)
    default: Sequence[int] = (0,)

    def answers_for(self, round_index: int, challenge: dict) -> Sequence[int]:
        if round_index < len(self.rounds):
            return self.rounds[round_index]
        return self.default


@dataclass
class ManualAnswers:
    """人工：从 stdin 读，或从回调拿（可插 UI）。"""
    prompt: Callable[[int, dict], str] | None = None

    def answers_for(self, round_index: int, challenge: dict) -> Sequence[int]:
        if self.prompt:
            raw = self.prompt(round_index, challenge)
        else:
            imgs = challenge.get("_challenge_imgs") or []
            print(f"[打码] 第 {round_index+1} 轮，{len(imgs)} 张图")
            for i, u in enumerate(imgs):
                print(f"   {i}: {u}")
            raw = input("输入下标(逗号分隔，如 0,2): ").strip()
        return [int(x) for x in raw.replace(" ", "").split(",") if x != ""]


@dataclass
class ScriptAnswers:
    """从文件读整段答案序列，每行一轮。"""
    path: str
    _loaded: Optional[List[List[int]]] = None

    def _ensure(self):
        if self._loaded is None:
            rows = []
            for ln in Path(self.path).read_text(encoding="utf-8").splitlines():
                ln = ln.strip()
                if ln:
                    rows.append([int(x) for x in ln.replace(" ", "").split(",") if x != ""])
            self._loaded = rows

    def answers_for(self, round_index: int, challenge: dict) -> Sequence[int]:
        self._ensure()
        return self._loaded[round_index] if round_index < len(self._loaded) else [0]


# ---------------------------------------------------------------------------
@dataclass
class YesCaptchaSolver:
    """YesCaptcha 兼容 HTTP 接口（你仓库 token-api/yescaptcha.go 也是这套格式）。"""
    client_key: str
    endpoint: str = "https://api.yescaptcha.com"
    timeout: int = 60
    poll_interval: float = 3.0
    max_wait: float = 120
    image_to_b64: bool = True

    def _post(self, path: str, payload: dict) -> dict:
        req = urllib.request.Request(
            self.endpoint.rstrip("/") + path,
            data=json.dumps(payload).encode(),
            headers={"content-type": "application/json"})
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            return json.loads(r.read().decode())

    def _wait(self, task_id) -> dict:
        t0 = time.time()
        while time.time() - t0 < self.max_wait:
            res = self._post("/getTaskResult",
                             {"clientKey": self.client_key, "taskId": task_id})
            if res.get("status") == "ready":
                return res.get("solution", {})
            if res.get("errorId"):
                raise RuntimeError(f"yescaptcha error: {res}")
            time.sleep(self.poll_interval)
        raise TimeoutError("yescaptcha 超时")

    def classify(self, image_b64: str, question: Optional[str] = None) -> List[int]:
        task = {"type": "FunCaptchaClassification", "image": image_b64}
        if question:
            task["question"] = question
        res = self._post("/createTask", {"clientKey": self.client_key, "softID": 136300, "task": task})
        if res.get("errorId"):
            raise RuntimeError(f"yescaptcha error: {res}")
        sol = self._wait(res["taskId"])
        objs = sol.get("objects") or sol.get("index") or []
        if isinstance(objs, (int, str)):
            objs = [objs]
        return [int(x) for x in objs]

    def funcaptcha_token(self, public_key: str, site_url: str,
                         *, blob: Optional[str] = None,
                         proxy: Optional[str] = None) -> str:
        task = {"type": "FunCaptchaTaskProxyless", "websiteURL": site_url,
                "websitePublicKey": public_key}
        if blob:
            task["data"] = json.dumps({"blob": blob})
        if proxy:
            task["type"] = "FunCaptchaTask"
            task["proxy"] = proxy
        res = self._post("/createTask", {"clientKey": self.client_key, "softID": 136300, "task": task})
        if res.get("errorId"):
            raise RuntimeError(f"yescaptcha error: {res}")
        sol = self._wait(res["taskId"])
        return sol.get("token", "")


@dataclass
class YesCaptchaAnswers:
    """把 YesCaptchaSolver 当 AnswerProvider 用：每轮对图片分类。"""
    solver: YesCaptchaSolver
    question: Optional[str] = None

    def answers_for(self, round_index: int, challenge: dict) -> Sequence[int]:
        imgs = challenge.get("_challenge_imgs") or []
        # 默认只对第一张（可切换答案的主图）分类；多图轮次由 question 指定
        img = imgs[0]
        if isinstance(img, str) and (img.startswith("http://") or img.startswith("https://")):
            import urllib.request as u
            with u.urlopen(img, timeout=30) as r:
                b64 = base64.b64encode(r.read()).decode()
        else:
            b64 = img
        return self.solver.classify(b64, self.question)


def make_provider(kind: str, **kw) -> AnswerProvider:
    if kind == "fixed":
        return FixedAnswers(**kw)
    if kind == "manual":
        return ManualAnswers(**kw)
    if kind == "script":
        return ScriptAnswers(**kw)
    if kind == "yescaptcha":
        return YesCaptchaAnswers(solver=YesCaptchaSolver(kw.pop("client_key"),
                                                         **kw))
    raise ValueError(f"unknown solver kind: {kind}")
