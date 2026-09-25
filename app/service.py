"""服务门面：串起密钥管理、签名验签与封存恢复，保证并发一致。"""
from __future__ import annotations

import threading
import time

from .keystore import KeyStore
from .models import KeyState, KeyVersion, SignedRequest, VerifyResult
from .signer import Signer
from . import vault


class KeyService:
    """对外统一入口；内部用同一把锁保证轮转与验签并发时结论唯一。"""

    def __init__(self, state_path: str = "keystore_state.json",
                 window_seconds: float = 300.0,
                 clock=time.time) -> None:
        self._lock = threading.RLock()
        self._clock = clock
        self.store = KeyStore(state_path)
        self.signer = Signer(self.store, window_seconds)
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
            return self.signer.sign(key_id, method, payload, self._clock(), nonce)

    def verify(self, req: SignedRequest) -> VerifyResult:
        with self._lock:
            return self.signer.verify(req, self._clock())

    # ---- 封存与恢复 ------------------------------------------------------
    def export(self, passphrase: str) -> bytes:
        with self._lock:
            versions = [v for key_id in list(self.store._keys)
                        for v in self.store.list_versions(key_id)]
            return vault.export_sealed(versions, passphrase)

    def restore(self, blob: bytes, passphrase: str) -> None:
        with self._lock:
            versions = vault.import_sealed(blob, passphrase)
            for v in versions:
                existing = self.store.list_versions(v.key_id)
                if any(e.version == v.version for e in existing):
                    continue  # 已存在的版本不覆盖
                self.store._keys.setdefault(v.key_id, []).append(v)
            for key_id in self.store._keys:
                self.store._keys[key_id].sort(key=lambda v: v.version)
            self.store.save()
