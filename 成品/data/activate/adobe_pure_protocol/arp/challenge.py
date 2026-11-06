"""Arkose 图片题（match-game）提交格式 —— 从 game-core 1.39.1 拆出。

对应行为：答完题后前端发 `POST {cdn}/fc/ca/`（form-urlencoded）。

golden（服务端校验的）字段：
    session_token  会话 token
    response       guesses[0]，本题所选（match-game 是下标数组，如 "0,2" 或 JSON）
    language       语言
    audio_type     固定 2
    r              随机数（对应 iframe 的 &r=）
    analytics_tier 埋点档位（如 40）
    bio            btoa(JSON({mbio,tbio,kbio}))   —— 鼠标/触摸/键盘生物特征
    ecdata         btoa(JSON({height,width}))     —— iframe 尺寸

三个来源对齐口径：
    golden = 真实浏览器/服务端接受的那份（抓包）
    solver = 打码服务解出来的 `response`
    mine   = 本模块生成的整包
目标：mine 除 `response` 外逐字段 == golden，`response` 换成解出来的即通过。

来源（chunk 68）：
    IP = {session_token, response: guesses[0], language, audio_type: 2, r,
          analytics_tier, bio: getBiometricsData(), ecdata: yC(state)}
    yC  = btoa(JSON.stringify({height, width}))
    bio = btoa(JSON.stringify({mbio,tbio,kbio}))  每项 "<t>,<dt>,<x>,<y>;"
"""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence
from urllib.parse import quote

# 提交顺序（与前端 Object.keys(IP).map(...).join("&") 一致）
CA_FIELDS = ["session_token", "response", "language", "audio_type", "r",
             "analytics_tier", "bio", "ecdata"]

# —— 鼠标/触摸/键盘事件字段顺序（game-core: "",t,dt,x,y 或 t,dt,code）——
MOUSE_KEYS = ("t", "dt", "x", "y")
TOUCH_KEYS = ("t", "dt", "x", "y")
KEY_KEYS = ("t", "dt", "code")


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def _events(items: Sequence[dict], keys: Sequence[str]) -> str:
    out = []
    for e in items:
        out.append(",".join(str(e.get(k, "")) for k in keys) + ";")
    return "".join(out)


def build_bio(mouse: Optional[Sequence[dict]] = None,
              touch: Optional[Sequence[dict]] = None,
              key: Optional[Sequence[dict]] = None) -> str:
    """btoa(JSON({mbio,tbio,kbio}))。空轨迹在无交互时是合法的。"""
    body = {
        "mbio": _events(mouse or [], MOUSE_KEYS),
        "tbio": _events(touch or [], TOUCH_KEYS),
        "kbio": _events(key or [], KEY_KEYS),
    }
    return _b64(json.dumps(body, separators=(",", ":")))


def build_ecdata(height: int = 400, width: int = 400) -> str:
    """btoa(JSON({height,width})) —— iframe 渲染尺寸。"""
    return _b64(json.dumps({"height": height, "width": width},
                           separators=(",", ":")))


def build_ca_body(*, session_token: str, response, language: str = "en",
                  r: str = "", analytics_tier: int = 40,
                  audio_type: int = 2,
                  bio: Optional[str] = None,
                  ecdata: Optional[str] = None,
                  height: int = 400, width: int = 400,
                  include_empty: bool = False) -> str:
    """生成 POST /fc/ca/ 的 form-urlencoded body。

    前端只拼接真值（`if (IU) return k+'='+encodeURIComponent(IU)`），
    所以空值字段默认不出现；include_empty=True 可强制保留以便对账。
    """
    if isinstance(response, (list, tuple)):
        response = ",".join(str(x) for x in response)
    fields = {
        "session_token": session_token,
        "response": response,
        "language": language,
        "audio_type": audio_type,
        "r": r,
        "analytics_tier": analytics_tier,
        "bio": bio if bio is not None else build_bio(),
        "ecdata": ecdata if ecdata is not None else build_ecdata(height, width),
    }
    parts = []
    for k in CA_FIELDS:
        v = fields.get(k)
        if v in (None, "") and not include_empty:
            continue
        parts.append(f"{k}={quote(str(v), safe='')}")
    return "&".join(parts)


def parse_body(body: str) -> Dict[str, str]:
    from urllib.parse import parse_qs
    return {k: v[0] for k, v in parse_qs(body, keep_blank_values=True).items()}


def compare_ca(golden: str, mine: str) -> List[dict]:
    """逐字段对账 golden vs mine。"""
    g, m = parse_body(golden), parse_body(mine)
    rows = []
    for k in CA_FIELDS:
        gv, mv = g.get(k), m.get(k)
        status = "SAME" if gv == mv else ("MISSING" if mv is None
                                          else ("EXTRA" if gv is None else "DIFF"))
        rows.append({"field": k, "status": status, "golden": gv, "mine": mv})
    for k in set(g) | set(m):
        if k not in CA_FIELDS:
            rows.append({"field": k, "status": "EXTRA", "golden": g.get(k), "mine": m.get(k)})
    return rows


def decode_bio(bio: str) -> dict:
    return json.loads(base64.b64decode(bio).decode())


def decode_ecdata(ecdata: str) -> dict:
    return json.loads(base64.b64decode(ecdata).decode())


def gfct_body(*, session_token: str, sid: str = "us-west-2",
              render_type: str = "canvas", lang: str = "en",
              is_audio_game: bool = False, compat: bool = False,
              api_breaker: str = "green", analytics_tier: int = 40) -> str:
    """POST /fc/gfct/ 取题（图片题）。"""
    return ("&".join([
        f"token={quote(session_token)}",
        f"sid={quote(sid)}",
        f"render_type={quote(render_type)}",
        f"lang={quote(lang)}",
        f"isAudioGame={'true' if is_audio_game else 'false'}",
        f"is_compatibility_mode={'true' if compat else 'false'}",
        f"apiBreakerVersion={quote(api_breaker)}",
        f"analytics_tier={analytics_tier}",
    ]))


# —— 真实（加密）提交包，2026 实测 ——
# 见 docs/ARKOSE_CA_ENCRYPT.md。字段顺序 = 浏览器抓包。
CA_FIELDS_ENC = ["session_token", "game_token", "sid", "guess", "render_type",
                 "analytics_tier", "bio", "is_compatibility_mode", "ecdata", "tguess"]


def build_ca_body_encrypted(*, session_token: str, game_token: str, guesses,
                            master: Optional[str] = None, sid: str = "ap-southeast-1",
                            render_type: str = "canvas", analytics_tier: int = 40,
                            bio: Optional[str] = None, compat: bool = False,
                            ecdata: Optional[str] = None,
                            height: int = 450, width: int = 400,
                            tguess=None) -> str:
    """生成**真实**的 POST /fc/ca/ body（guess 为 {ct,iv,s} 密文）。

    `master` 默认取 session_token 本身（实测：buildKey(session_token, s)）。
    这就是以前发明文 `response=` 导致 `DENIED ACCESS` 的根本原因。
    """
    from . import guesscrypto as G
    master = master or session_token
    if isinstance(guesses, int):
        guesses = [{"index": guesses}]
    elif guesses and isinstance(guesses[0], int):
        guesses = [{"index": n} for n in guesses]
    gp = G.encrypt_payload(guesses, master)
    fields = {
        "session_token": session_token,
        "game_token": game_token,
        "sid": sid,
        "guess": json.dumps(gp, separators=(",", ":")),
        "render_type": render_type,
        "analytics_tier": analytics_tier,
        "bio": bio if bio is not None else build_bio(),
        "is_compatibility_mode": "true" if compat else "false",
        "ecdata": ecdata if ecdata is not None else build_ecdata(height, width),
    }
    if tguess is not None:
        tg = G.encrypt_payload(tguess, master)
        fields["tguess"] = json.dumps(tg, separators=(",", ":"))
    parts = []
    for k in CA_FIELDS_ENC:
        if k in fields:
            parts.append(f"{k}={quote(str(fields[k]), safe='')}")
    return "&".join(parts)


def decrypt_guess(body: str, master: str):
    """从 ca body 解出 guess 明文（对账/取证用）。"""
    from . import guesscrypto as G
    d = parse_body(body)
    return G.decrypt_payload(json.loads(d["guess"]), master)


@dataclass
class ChallengeSubmission:
    """一次图片题提交的完整包（golden/solver/mine 共用结构）。"""
    session_token: str
    response: Sequence[int]
    language: str = "en"
    r: str = ""
    analytics_tier: int = 40
    bio: str = field(default_factory=build_bio)
    ecdata: str = field(default_factory=build_ecdata)

    def body(self) -> str:
        return build_ca_body(session_token=self.session_token, response=self.response,
                             language=self.language, r=self.r,
                             analytics_tier=self.analytics_tier,
                             bio=self.bio, ecdata=self.ecdata)

    def headers(self) -> Dict[str, str]:
        return {"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "Accept": "*/*", "Cache-Control": "no-cache",
                "X-Requested-With": "XMLHttpRequest"}
