"""核心类型定义：密钥状态、失败原因、数据结构。"""
from __future__ import annotations

import enum
import hashlib
from dataclasses import dataclass, field


class KeyState(str, enum.Enum):
    """密钥版本的生命周期状态。"""

    PENDING = "pending"        # 待启用：已生成，未生效
    ACTIVE = "active"          # 启用：可签名可验签
    VERIFY_ONLY = "verify_only"  # 只验签：过渡期内仅可验签
    REVOKED = "revoked"        # 已吊销：任何使用均拒绝


class FailureReason(str, enum.Enum):
    """可区分的失败原因分类。"""

    KEY_NOT_FOUND = "key_not_found"
    KEY_PENDING = "key_pending"                # 密钥尚未启用
    KEY_VERIFY_ONLY = "key_verify_only"        # 只验签状态不可用于签名
    KEY_REVOKED = "key_revoked"                # 已吊销
    TRANSITION_EXPIRED = "transition_expired"  # 过渡期结束
    ILLEGAL_TRANSITION = "illegal_transition"  # 非法状态迁移
    TIMESTAMP_OUT_OF_WINDOW = "timestamp_out_of_window"  # 超出时间窗
    NONCE_REUSED = "nonce_reused"              # 随机数重复使用
    SIGNATURE_MISMATCH = "signature_mismatch"  # 签名不匹配
    WRONG_PASSPHRASE = "wrong_passphrase"      # 口令错误或密文篡改
    CORRUPT_ARCHIVE = "corrupt_archive"        # 归档结构/版本关系不完整


# 允许的状态迁移表：源状态 -> 允许的目标状态集合
ALLOWED_TRANSITIONS: dict[KeyState, frozenset[KeyState]] = {
    KeyState.PENDING: frozenset({KeyState.ACTIVE, KeyState.REVOKED}),
    KeyState.ACTIVE: frozenset({KeyState.VERIFY_ONLY, KeyState.REVOKED}),
    KeyState.VERIFY_ONLY: frozenset({KeyState.REVOKED}),
    KeyState.REVOKED: frozenset(),
}


@dataclass
class KeyVersion:
    """一个密钥版本的本地状态记录。"""

    key_id: str
    version: int
    state: KeyState
    public_key_pem: bytes
    private_key_pem: bytes | None  # 仅本地保存，导出时封存
    created_at: float
    activated_at: float | None = None
    verify_only_until: float | None = None  # 过渡期截止时间
    revoked_at: float | None = None
    predecessor_version: int | None = None  # 版本链关系

    def fingerprint(self) -> str:
        return "sha256:" + hashlib.sha256(self.public_key_pem).hexdigest()


@dataclass
class SignedRequest:
    """一次签名请求的要素。"""

    method: str
    payload: bytes
    key_id: str
    version: int
    timestamp: float
    nonce: str
    signature: bytes = b""

    def canonical_bytes(self) -> bytes:
        parts = [
            self.method.encode("utf-8"),
            self.key_id.encode("utf-8"),
            str(self.version).encode("ascii"),
            str(self.timestamp).encode("ascii"),
            self.nonce.encode("utf-8"),
            self.payload,
        ]
        return b"\n".join(len(p).to_bytes(8, "big") + p for p in parts)


@dataclass
class VerifyResult:
    """验签/操作结论：成功或带可区分原因的失败。"""

    ok: bool
    reason: FailureReason | None = None
    detail: str = ""
