"""arp —— Arkose FunCaptcha 三来源对齐沙箱。

    golden : 对方要校验的（真浏览器打通的那一次）
    solver : 打码服务结果/回显
    mine   : 我方沙箱生成的

子模块：crypto / hashing / model / loaders / compare / validate / report
"""
from __future__ import annotations

# 先绑定子模块，避免与同名函数相互遮蔽
from . import compare, crypto, loaders, model, report, validate
from . import hash as hashing
from . import capture, client, fp_pool, generate, keys, solver, pure

from .model import CATALOG, REQUEST_39, Capture, Exchange, FieldSpec
from .crypto import (arkose_encrypt_fp, arkose_decrypt_fp, split_arkose_c,
                     arkose_esync_timestamp, newrelic_timestamp,
                     cryptojs_encrypt, cryptojs_decrypt, cryptojs_probe,
                     evp_bytes_to_key, requested_id_key)
from .compare import compare as compare_captures, CompareResult, Row
from .validate import validate as validate_capture, validate_fp as validate_fingerprint, Finding
from .loaders import load
from .generate import SessionSeed, build_mine, new_fingerprint
from .fp_pool import FingerprintPool

__all__ = [
    "CATALOG", "REQUEST_39", "Capture", "Exchange", "FieldSpec",
    "arkose_encrypt_fp", "arkose_decrypt_fp", "split_arkose_c",
    "arkose_esync_timestamp", "newrelic_timestamp",
    "cryptojs_encrypt", "cryptojs_decrypt", "cryptojs_probe",
    "evp_bytes_to_key", "requested_id_key",
    "compare_captures", "CompareResult", "Row",
    "validate_capture", "validate_fingerprint", "Finding",
    "load",
    "SessionSeed", "build_mine", "new_fingerprint", "FingerprintPool",
    "compare", "crypto", "loaders", "model", "report", "validate", "hashing",
    "capture", "client", "fp_pool", "generate", "keys", "solver", "pure",
]
__version__ = "0.1.0"
