"""失败原因分类：所有可区分的拒绝原因集中定义在此。

判定依据与错误码一一对应，测试与文档均以这里的名称为准。
"""

from __future__ import annotations

import enum


class ErrorCode(enum.Enum):
    """业务失败原因（稳定字符串，供日志/HTTP 响应/测试断言使用）。"""

    KEY_VERSION_NOT_FOUND = "KEY_VERSION_NOT_FOUND"
    NO_ACTIVE_KEY = "NO_ACTIVE_KEY"
    ILLEGAL_TRANSITION = "ILLEGAL_TRANSITION"
    KEY_PENDING = "KEY_PENDING"
    KEY_RETIRED = "KEY_RETIRED"
    KEY_REVOKED = "KEY_REVOKED"
    KEY_VERIFY_WINDOW_EXPIRED = "KEY_VERIFY_WINDOW_EXPIRED"
    SKEW_TOO_OLD = "SKEW_TOO_OLD"
    SKEW_IN_FUTURE = "SKEW_IN_FUTURE"
    SIGNATURE_MISMATCH = "SIGNATURE_MISMATCH"
    NONCE_REPLAY = "NONCE_REPLAY"
    BAD_PASSWORD = "BAD_PASSWORD"
    SEAL_TAMPERED = "SEAL_TAMPERED"
    INCOMPLETE_VERSION_SET = "INCOMPLETE_VERSION_SET"
    FINGERPRINT_MISMATCH = "FINGERPRINT_MISMATCH"
    STATE_CORRUPT = "STATE_CORRUPT"


class KeyServiceError(Exception):
    """所有可解释的业务错误基类。

    code: 稳定的失败原因码
    reason: 面向调用方的一句话解释
    """

    def __init__(self, code: ErrorCode, reason: str) -> None:
        self.code = code
        self.reason = reason
        super().__init__(f"{code.value}: {reason}")
