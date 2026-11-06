"""规范化数据模型 + 参数目录（对齐 haloowhite 文章的 4 步链路）。

三个来源统一成同一个 Capture 结构，才能做逐字段 diff：
    golden : 对方要校验的（真浏览器打通的那一次）
    solver : 打码服务返回/回显的
    mine   : 我方沙箱生成的
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# 链路阶段
# ---------------------------------------------------------------------------
STAGES = ["gt2", "pow", "gfct", "ca"]

STAGE_MATCH = {
    "gt2": re.compile(r"/fc/gt2/public_key/", re.I),
    "pow": re.compile(r"/fc/pow", re.I),
    "gfct": re.compile(r"/fc/gfct", re.I),
    "ca": re.compile(r"/fc/ca\b", re.I),
}


def stage_of(url: str) -> str:
    for name, rx in STAGE_MATCH.items():
        if rx.search(url or ""):
            return name
    return "other"


# ---------------------------------------------------------------------------
# 参数目录：category 决定 diff 时怎么比
#   value    -> 必须逐字节相同
#   volatile -> 每次不同（随机数/时间戳/一次性 token），只比形状
#   secret   -> 加密串，需解密后再比（或只比结构）
#   fp       -> 设备指纹明文
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class FieldSpec:
    stage: str
    where: str          # query | body | header | url
    name: str
    category: str = "value"
    note: str = ""


# 文章里逐条点名过的参数，作为"必须对齐"的骨架。
CATALOG: List[FieldSpec] = [
    # ---- 步骤1 gt2 ----
    FieldSpec("gt2", "query", "public_key", "value", "站点业务场景标识（在 URL path 里）"),
    FieldSpec("gt2", "header", "x-ark-esync-value", "volatile", "21600ms 对齐"),
    FieldSpec("gt2", "body", "c", "secret", "设备指纹密文 AES-GCM+RSA-OAEP"),
    FieldSpec("gt2", "body", "userbrowser", "value", "UA，必须与指纹一致"),
    FieldSpec("gt2", "body", "rnd", "volatile", "随机数"),
    FieldSpec("gt2", "body", "style_theme", "value", ""),
    FieldSpec("gt2", "body", "capi_mode", "value", ""),
    FieldSpec("gt2", "body", "public_key", "value", ""),
    FieldSpec("gt2", "body", "site", "value", "必须与网页端一致"),
    FieldSpec("gt2", "body", "data[blob]", "value", "后端下传，缺失即 undefined"),
    # ---- 步骤2 gfct ----
    FieldSpec("gfct", "body", "token", "volatile", "步骤1响应 | 前段"),
    FieldSpec("gfct", "body", "sid", "volatile", "步骤1响应 sid"),
    FieldSpec("gfct", "body", "lang", "value", ""),
    FieldSpec("gfct", "body", "render_type", "value", ""),
    FieldSpec("gfct", "body", "isAudioGame", "value", ""),
    FieldSpec("gfct", "body", "is_compatibility_mode", "value", ""),
    FieldSpec("gfct", "body", "apiBreakerVersion", "value", ""),
    FieldSpec("gfct", "body", "analytics_tier", "value", ""),
    FieldSpec("gfct", "header", "x-newrelic-timestamp", "volatile", "前7+00+后6"),
    # ---- 步骤3 ca ----
    FieldSpec("ca", "body", "session_token", "volatile", "步骤1响应 token"),
    FieldSpec("ca", "body", "game_token", "volatile", "步骤2 game_token"),
    FieldSpec("ca", "body", "guess", "secret", '[{"index":N},...]'),
    FieldSpec("ca", "body", "tguess", "secret", "每版 js 明文不同"),
    FieldSpec("ca", "body", "bio", "secret", "交互数据"),
    FieldSpec("ca", "body", "render_type", "value", ""),
    FieldSpec("ca", "body", "analytics_tier", "value", ""),
    FieldSpec("ca", "body", "is_compatibility_mode", "value", ""),
    FieldSpec("ca", "header", "x-newrelic-timestamp", "volatile", "同步骤2"),
    FieldSpec("ca", "header", "x-requested-id", "secret", "密钥 REQUESTED{token}ID"),
]

# 顶层设备指纹信号（Arkose FP docs）。用户自己的 39 项清单可直接覆盖它。
FP_SIGNALS_TOP = ["api_type", "f", "n", "wh", "enhanced_fp", "fe", "ife_hash", "jsbd", "c"]

# 常见的 39 项 request 参数（文章 + 各站点实测并集），供 --expect-39 自检。
REQUEST_39 = [
    "gt2.query.public_key", "gt2.header.x-ark-esync-value",
    "gt2.body.c", "gt2.body.userbrowser", "gt2.body.rnd",
    "gt2.body.style_theme", "gt2.body.capi_mode", "gt2.body.public_key",
    "gt2.body.site", "gt2.body.data[blob]",
    "gfct.body.token", "gfct.body.sid", "gfct.body.lang", "gfct.body.render_type",
    "gfct.body.isAudioGame", "gfct.body.is_compatibility_mode",
    "gfct.body.apiBreakerVersion", "gfct.body.analytics_tier",
    "gfct.header.x-newrelic-timestamp",
    "ca.body.session_token", "ca.body.game_token", "ca.body.guess",
    "ca.body.tguess", "ca.body.bio", "ca.body.render_type",
    "ca.body.analytics_tier", "ca.body.is_compatibility_mode",
    "ca.header.x-newrelic-timestamp", "ca.header.x-requested-id",
    "ca.header.content-type", "gt2.header.content-type", "gfct.header.content-type",
    "gt2.header.origin", "gt2.header.referer", "gt2.header.user-agent",
    "ca.header.user-agent", "gfct.header.user-agent",
    "gt2.header.accept-language", "ca.header.accept-language",
]


# ---------------------------------------------------------------------------
# 数据模型
# ---------------------------------------------------------------------------
@dataclass
class Exchange:
    stage: str
    method: str = "POST"
    url: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    query: Dict[str, str] = field(default_factory=dict)
    body: Dict[str, str] = field(default_factory=dict)
    raw_body: Optional[str] = None
    status: Optional[int] = None
    resp_json: Optional[dict] = None
    resp_text: Optional[str] = None
    tls: Optional[dict] = None
    note: str = ""

    def to_view(self) -> Dict[str, Any]:
        """拍平成 'stage.where.name' -> value，供 diff 使用。"""
        out: Dict[str, Any] = {}
        for k, v in self.query.items():
            out[f"{self.stage}.query.{k}"] = v
        for k, v in self.body.items():
            out[f"{self.stage}.body.{k}"] = v
        for k, v in self.headers.items():
            out[f"{self.stage}.header.{k.lower()}"] = v
        if self.tls:
            for k, v in self.tls.items():
                out[f"{self.stage}.tls.{k}"] = v
        if self.status is not None:
            out[f"{self.stage}.resp.status"] = self.status
        return out


@dataclass
class Capture:
    name: str                 # golden | solver | mine | ...
    kind: str = "unknown"     # har | netlog | json | raw | generator
    exchanges: List[Exchange] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)
    fp: Optional[dict] = None          # 若拿得到设备指纹明文
    session_token: Optional[str] = None

    def by_stage(self, stage: str) -> Optional[Exchange]:
        for e in self.exchanges:
            if e.stage == stage:
                return e
        return None

    def view(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for e in self.exchanges:
            out.update(e.to_view())
        return out
