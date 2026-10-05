"""服务门面：串起密钥管理、签名验签、请求流水与封存恢复。

多进程/重启语义：
- 所有变更（生命周期、验签记录流水）在 StateStore 事务内完成：
  排他文件锁 + 重载 + 变更 + 原子落盘，多进程共用同一状态文件时
  同一 nonce 最多被一个进程放行，重启后重复判定不变。
- 查询与导出只读（共享锁重载，不落盘），不改变任何判定状态。
"""
from __future__ import annotations

import threading
import time

from . import vault
from .keystore import KeyStore
from .ledger import RequestLedger
from .models import (
    KeyVersion,
    LedgerConfig,
    LedgerRecord,
    SignedRequest,
    VerifyResult,
)
from .signer import Signer
from .state import StateStore

DEFAULT_LEDGER_MAX_RECORDS = 100_000


class KeyService:
    """对外统一入口；内部用同一把锁保证轮转与验签并发时结论唯一。"""

    def __init__(self, state_path: str = "keystore_state.json",
                 window_seconds: float = 300.0,
                 clock=time.time,
                 ledger_retention_seconds: float | None = None,
                 ledger_max_records: int = DEFAULT_LEDGER_MAX_RECORDS) -> None:
        self._lock = threading.RLock()
        self._clock = clock
        self._state = StateStore(state_path)
        self.store = KeyStore(state_store=self._state)
        # 保留期不得短于验签时间窗，否则窗口内的重放判定会丢记录
        retention = max(ledger_retention_seconds
                        if ledger_retention_seconds is not None
                        else window_seconds,
                        window_seconds)
        self.ledger = RequestLedger(
            LedgerConfig(retention_seconds=retention,
                         max_records=ledger_max_records),
            records=self._state.ledger)
        self.signer = Signer(self.store, window_seconds, self.ledger)
        # 签名器与服务共用一把锁：验签/签名/轮转互斥，结论唯一
        self.signer.bind_lock(self._lock)

    # ---- 生命周期 ------------------------------------------------------
    def create_key(self, key_id: str) -> KeyVersion:
        with self._lock:
            return self.store.create_key(key_id, self._clock())

    def activate(self, key_id: str, version: int) -> KeyVersion:
        with self._lock:
            return self.store.activate(key_id, version, self._clock())

    def rotate(self, key_id: str, transition_seconds: float) -> KeyVersion:
        with self._lock:
            return self.store.rotate(key_id, self._clock(), transition_seconds)

    def revoke(self, key_id: str, version: int) -> KeyVersion:
        with self._lock:
            return self.store.revoke(key_id, version, self._clock())

    def refresh(self) -> None:
        with self._lock:
            self.store.refresh(self._clock())

    # ---- 签名与验签 ------------------------------------------------------
    def sign(self, key_id: str, method: str, payload: bytes,
             nonce: str | None = None) -> SignedRequest | VerifyResult:
        with self._lock:
            self._state.reload_readonly()  # 读到其它进程最新的轮转结果
            return self.signer.sign(key_id, method, payload, self._clock(), nonce)

    def verify(self, req: SignedRequest) -> VerifyResult:
        # 事务内完成 重载->检查->记流水->落盘：跨进程原子，重启不丢结论
        with self._lock, self._state.transaction():
            return self.signer.verify(req, self._clock())

    # ---- 请求流水：清理 / 查询 / 对账导出 --------------------------------
    def sweep_ledger(self) -> int:
        """主动清理保留期外的流水记录，返回清理条数。"""
        with self._lock, self._state.transaction():
            return self.ledger.sweep(self._clock())

    def query_ledger(self, key_id: str | None = None,
                     version: int | None = None,
                     start: float | None = None,
                     end: float | None = None) -> list[LedgerRecord]:
        """按密钥/版本/判定时间范围查询流水（只读，不改判定状态）。"""
        with self._lock:
            self._state.reload_readonly()
            return self.ledger.query(key_id=key_id, version=version,
                                     start=start, end=end)

    def export_ledger_manifest(self) -> bytes:
        """导出确定性对账清单：无私钥材料，重复导出字节一致。"""
        with self._lock:
            self._state.reload_readonly()
            return self.ledger.export_manifest()

    # ---- 封存与恢复 ------------------------------------------------------
    def export(self, passphrase: str) -> bytes:
        with self._lock:
            self._state.reload_readonly()
            versions = [v for key_id in list(self.store._keys)
                        for v in self.store.list_versions(key_id)]
            return vault.export_sealed(versions, passphrase)

    def restore(self, blob: bytes, passphrase: str) -> None:
        with self._lock, self._state.transaction():
            versions = vault.import_sealed(blob, passphrase)
            for v in versions:
                existing = self.store.list_versions(v.key_id)
                if any(e.version == v.version for e in existing):
                    continue  # 已存在的版本不覆盖
                self.store._keys.setdefault(v.key_id, []).append(v)
            for key_id in self.store._keys:
                self.store._keys[key_id].sort(key=lambda v: v.version)
