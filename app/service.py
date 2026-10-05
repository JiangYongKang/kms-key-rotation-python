"""服务门面：串起密钥管理、签名验签、封存恢复与审计，保证多进程一致。

并发与持久化：
- 所有判定与变更都在 ``store.exclusive()``（进程内锁 + flock）内执行，
  且进入段后重读磁盘，因此多个工作进程共享同一状态文件时：
  * 同一 nonce 最多只有一个进程判为接受；
  * 密钥版本变化与请求流水在同一次原子写盘里一起生效。
- 保留期与容量上限在构造时配置；保留期不应短于验签时间窗，否则时间窗内
  的重放可能被当新请求放行（这里强制校验）。
"""
from __future__ import annotations

import logging
import threading
import time

from .audit import Auditor
from .keystore import KeyStore
from .models import AuditFilter, KeyVersion, NonceRecord, SignedRequest, VerifyResult
from .signer import Signer
from . import vault

log = logging.getLogger("kms.service")


class KeyService:
    """对外统一入口；进程内锁 + 文件锁保证多进程下结论唯一且状态原子。"""

    def __init__(self, state_path: str = "keystore_state.json",
                 window_seconds: float = 300.0,
                 retention_seconds: float | None = None,
                 nonce_capacity: int = 1_000_000,
                 clock=time.time) -> None:
        retention = window_seconds if retention_seconds is None else retention_seconds
        if retention < window_seconds:
            # 保留期覆盖时间窗：窗口内的请求其 nonce 必须仍可被判定为重复
            raise ValueError(
                f"retention_seconds ({retention}) must be >= "
                f"window_seconds ({window_seconds})")
        self._clock = clock
        self.store = KeyStore(state_path, retention, nonce_capacity)
        self.signer = Signer(self.store, window_seconds)
        self.auditor = Auditor()
        # 一把线程锁串起 store / journal / signer；跨进程再由 flock 互斥
        self._lock = threading.RLock()
        self.store.bind_lock(self._lock)
        self.signer.bind_lock(self._lock)

    # ---- 生命周期 ------------------------------------------------------
    def create_key(self, key_id: str) -> KeyVersion:
        with self.store.exclusive():
            return self.store.create_key(key_id, self._clock())

    def activate(self, key_id: str, version: int) -> KeyVersion:
        with self.store.exclusive():
            return self.store.activate(key_id, version, self._clock())

    def rotate(self, key_id: str, transition_seconds: float) -> KeyVersion:
        with self.store.exclusive():
            return self.store.rotate(key_id, self._clock(), transition_seconds)

    def revoke(self, key_id: str, version: int) -> KeyVersion:
        with self.store.exclusive():
            return self.store.revoke(key_id, version, self._clock())

    def refresh(self) -> None:
        """推进生命周期并清理保留期外流水；只切过期前缀，不长时间阻塞。"""
        with self.store.exclusive():
            now = self._clock()
            self.store.refresh(now)
            removed = self.store.journal.evict(now)
            if removed:
                self.store.save()
                log.info("refresh evicted %d expired record(s)", removed)

    # ---- 签名与验签 ------------------------------------------------------
    def sign(self, key_id: str, method: str, payload: bytes,
             nonce: str | None = None) -> SignedRequest | VerifyResult:
        with self.store.exclusive():
            return self.signer.sign(key_id, method, payload, self._clock(), nonce)

    def verify(self, req: SignedRequest) -> VerifyResult:
        with self.store.exclusive():
            return self.signer.verify(req, self._clock())

    # ---- 审计：只读，不改变任何判定状态 -----------------------------------
    def query_records(self, key_id: str | None = None, version: int | None = None,
                      start: float | None = None,
                      end: float | None = None) -> list[NonceRecord]:
        flt = AuditFilter(key_id=key_id, version=version, start=start, end=end)
        with self.store.exclusive():
            return self.store.journal.query(flt)

    def export_audit(self) -> bytes:
        """导出确定性的离线对账清单（不含私钥明文）。"""
        with self.store.exclusive():
            records = self.store.journal.query(None)
            versions = self.store.all_versions()
            return self.auditor.export(records, versions)

    # ---- 封存与恢复 ------------------------------------------------------
    def export(self, passphrase: str) -> bytes:
        with self.store.exclusive():
            return vault.export_sealed(self.store.all_versions(), passphrase)

    def restore(self, blob: bytes, passphrase: str) -> None:
        with self.store.exclusive():
            versions = vault.import_sealed(blob, passphrase)
            for v in versions:
                existing = self.store.list_versions(v.key_id)
                if any(e.version == v.version for e in existing):
                    continue  # 已存在的版本不覆盖
                self.store._keys.setdefault(v.key_id, []).append(v)
            for key_id in self.store._keys:
                self.store._keys[key_id].sort(key=lambda v: v.version)
            self.store.save()
