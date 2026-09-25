"""密钥多版本与生命周期的类型定义。

状态机（非法迁移一律拒绝，原因码 ILLEGAL_TRANSITION）：
    PENDING -> ACTIVE
    PENDING -> REVOKED
    ACTIVE -> VERIFY_ONLY
    ACTIVE -> REVOKED
    VERIFY_ONLY -> REVOKED
    REVOKED 为终态

各状态在“验签请求”路径上的可区分结论：
    PENDING            -> KEY_PENDING
    ACTIVE             -> 允许进入后续时间窗/签名/nonce 判定
    VERIFY_ONLY 未过期  -> 同上
    VERIFY_ONLY 已过期  -> KEY_VERIFY_WINDOW_EXPIRED
    REVOKED            -> KEY_REVOKED
"""

from __future__ import annotations

import dataclasses
import enum
import hashlib
from typing import Optional


class KeyState(enum.Enum):
    PENDING = "PENDING"            # 待启用：不可签名、不可验签
    ACTIVE = "ACTIVE"              # 启用：可签名、可验签
    VERIFY_ONLY = "VERIFY_ONLY"    # 只验签：轮转过渡，不可签名、可在过渡期内验签
    REVOKED = "REVOKED"            # 已吊销：不可签名、不可验签


# 允许的状态迁移表
ALLOWED_TRANSITIONS: dict[KeyState, frozenset[KeyState]] = {
    KeyState.PENDING: frozenset({KeyState.ACTIVE, KeyState.REVOKED}),
    KeyState.ACTIVE: frozenset({KeyState.VERIFY_ONLY, KeyState.REVOKED}),
    KeyState.VERIFY_ONLY: frozenset({KeyState.REVOKED}),
    KeyState.REVOKED: frozenset(),
}


@dataclasses.dataclass
class KeyMaterial:
    """一个密钥版本的材料与生命周期元数据。"""

    version: int
    public_bytes: bytes
    private_bytes: bytes                 # Ed25519 裸私钥种子（32B），本地状态持久化
    state: KeyState
    created_at: int                      # UNIX 秒
    verify_until: Optional[int] = None   # VERIFY_ONLY 过渡期截止 UNIX 秒；None 表示无截止

    def fingerprint(self) -> str:
        """公钥指纹：SHA-256(public_bytes) 十六进制；恢复后须可复现。"""
        return hashlib.sha256(self.public_bytes).hexdigest()
