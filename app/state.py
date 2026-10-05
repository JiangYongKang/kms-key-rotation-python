"""共享状态文件：密钥版本与请求流水同一份文档，原子落盘 + 跨进程锁。

状态文件格式：
- v2: {"format": "kms-state-v2", "keys": {...}, "ledger": [...]}
- v1（历史格式，仅密钥的裸字典）加载时自动升级，保存时统一写 v2。

多进程安全：所有变更在 ``transaction()`` 内完成——先对 ``<state>.lock``
加排他文件锁，再从磁盘重载最新状态，变更后原子落盘（临时文件 +
``os.replace``），最后释放锁。密钥版本变化与请求流水写在同一份文档里，
要么一起生效要么一起不生效，重启后两边不会对不上。
"""
from __future__ import annotations

import base64
import fcntl
import json
import os
import threading
from collections.abc import Iterator
from contextlib import contextmanager

from .models import KeyState, KeyVersion, LedgerRecord

STATE_FORMAT_V2 = "kms-state-v2"


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def key_version_to_dict(v: KeyVersion) -> dict:
    return {
        "version": v.version,
        "state": v.state.value,
        "public_key_pem": _b64e(v.public_key_pem),
        "private_key_pem": _b64e(v.private_key_pem)
        if v.private_key_pem is not None else None,
        "created_at": v.created_at,
        "activated_at": v.activated_at,
        "verify_only_until": v.verify_only_until,
        "revoked_at": v.revoked_at,
        "predecessor_version": v.predecessor_version,
    }


def key_version_from_dict(key_id: str, item: dict) -> KeyVersion:
    return KeyVersion(
        key_id=key_id, version=item["version"],
        state=KeyState(item["state"]),
        public_key_pem=_b64d(item["public_key_pem"]),
        private_key_pem=(_b64d(item["private_key_pem"])
                         if item.get("private_key_pem") else None),
        created_at=item["created_at"],
        activated_at=item.get("activated_at"),
        verify_only_until=item.get("verify_only_until"),
        revoked_at=item.get("revoked_at"),
        predecessor_version=item.get("predecessor_version"),
    )


def ledger_record_to_dict(r: LedgerRecord) -> dict:
    return {
        "nonce": r.nonce,
        "key_id": r.key_id,
        "version": r.version,
        "request_timestamp": r.request_timestamp,
        "decided_at": r.decided_at,
        "decision": r.decision,
        "basis": r.basis,
        "reason": r.reason,
    }


def ledger_record_from_dict(item: dict) -> LedgerRecord:
    return LedgerRecord(
        nonce=item["nonce"], key_id=item["key_id"], version=item["version"],
        request_timestamp=item["request_timestamp"],
        decided_at=item["decided_at"], decision=item["decision"],
        basis=item["basis"], reason=item.get("reason"),
    )


class StateStore:
    """持有密钥与流水的内存视图，负责落盘与跨进程互斥。"""

    def __init__(self, state_path: str) -> None:
        self._lock = threading.RLock()       # 进程内互斥
        self._state_path = state_path
        self._lock_path = state_path + ".lock"
        self.keys: dict[str, list[KeyVersion]] = {}
        self.ledger: list[LedgerRecord] = []

    # ---- 跨进程事务 ----------------------------------------------------
    @contextmanager
    def transaction(self) -> Iterator[None]:
        """排他事务：文件锁 -> 重载 -> 变更 -> 原子落盘 -> 释放。

        进程内先拿 RLock（可重入，便于事务内调用其它加锁方法），
        再拿跨进程文件锁；落盘失败时锁照样释放，磁盘上仍是旧版本文档。
        """
        with self._lock:
            os.makedirs(os.path.dirname(os.path.abspath(self._lock_path)),
                        exist_ok=True)
            with open(self._lock_path, "a+b") as lock_file:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
                try:
                    self.load()
                    yield
                    self.save()
                finally:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

    # ---- 持久化 --------------------------------------------------------
    def load(self) -> None:
        """从磁盘加载（自动兼容 v1 裸密钥字典），文件不存在则置空。

        原地更新（clear + 填充），保证外部持有的 keys/ledger 引用
        （如 RequestLedger 的记录列表）在重载后仍然有效。
        """
        with self._lock:
            if not os.path.exists(self._state_path):
                self.keys.clear()
                del self.ledger[:]
                return
            with open(self._state_path, encoding="utf-8") as f:
                data = json.load(f)
            if data.get("format") == STATE_FORMAT_V2:
                keys_doc = data["keys"]
                ledger_doc = data.get("ledger", [])
            else:  # v1：整个文档就是 key_id -> [版本...] 的裸字典，无流水
                keys_doc = data
                ledger_doc = []
            self.keys.clear()
            self.keys.update({
                key_id: [key_version_from_dict(key_id, item) for item in items]
                for key_id, items in keys_doc.items()
            })
            del self.ledger[:]
            self.ledger.extend(ledger_record_from_dict(it) for it in ledger_doc)

    def reload_readonly(self) -> None:
        """只读重载：共享文件锁 + 不落盘，用于查询/导出前刷新视图。"""
        with self._lock:
            os.makedirs(os.path.dirname(os.path.abspath(self._lock_path)),
                        exist_ok=True)
            with open(self._lock_path, "a+b") as lock_file:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_SH)
                try:
                    self.load()
                finally:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

    def save(self) -> None:
        """原子落盘：密钥与流水写入同一份文档，同生共死。"""
        with self._lock:
            doc = {
                "format": STATE_FORMAT_V2,
                "keys": {
                    key_id: [key_version_to_dict(v) for v in versions]
                    for key_id, versions in self.keys.items()
                },
                "ledger": [ledger_record_to_dict(r) for r in self.ledger],
            }
            tmp = self._state_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(doc, f, indent=2, sort_keys=True)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self._state_path)
