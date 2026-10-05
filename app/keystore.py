"""密钥多版本与生命周期管理；状态经 StateStore 落盘并支持多进程互斥。"""
from __future__ import annotations

import threading

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .models import ALLOWED_TRANSITIONS, KeyState, KeyVersion
from .state import StateStore


class IllegalTransitionError(Exception):
    """非法状态迁移。"""

    def __init__(self, key_id: str, version: int, src: KeyState, dst: KeyState) -> None:
        self.key_id, self.version, self.src, self.dst = key_id, version, src, dst
        super().__init__(
            f"illegal transition {src.value}->{dst.value} for {key_id} v{version}")


class KeyStore:
    """管理密钥版本链与状态迁移。

    所有变更在 StateStore 事务内完成（文件锁 + 重载 + 原子落盘），
    多进程共用同一状态文件时不会互相覆盖；查询读内存视图。
    """

    def __init__(self, state_path: str = "keystore_state.json",
                 state_store: StateStore | None = None) -> None:
        self._lock = threading.RLock()
        self._state = state_store if state_store is not None \
            else StateStore(state_path)

    # ---- 兼容视图 ------------------------------------------------------
    @property
    def _keys(self) -> dict[str, list[KeyVersion]]:
        return self._state.keys

    @property
    def state_store(self) -> StateStore:
        return self._state

    # ---- 密钥生成 ------------------------------------------------------
    @staticmethod
    def _generate_keypair() -> tuple[bytes, bytes]:
        priv = Ed25519PrivateKey.generate()
        priv_pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_pem = priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return pub_pem, priv_pem

    def _new_version(self, key_id: str, version: int, now: float,
                     predecessor: int | None) -> KeyVersion:
        pub_pem, priv_pem = self._generate_keypair()
        return KeyVersion(
            key_id=key_id, version=version, state=KeyState.PENDING,
            public_key_pem=pub_pem, private_key_pem=priv_pem,
            created_at=now, predecessor_version=predecessor,
        )

    # ---- 生命周期（公开方法各自开启事务，内部 *_locked 复用） ------------
    def create_key(self, key_id: str, now: float) -> KeyVersion:
        """生成首个版本（PENDING）。key_id 已存在则报错。"""
        with self._lock, self._state.transaction():
            if key_id in self._state.keys:
                raise ValueError(f"key {key_id!r} already exists")
            kv = self._new_version(key_id, 1, now, predecessor=None)
            self._state.keys[key_id] = [kv]
            return self._snapshot(kv)

    def activate(self, key_id: str, version: int, now: float) -> KeyVersion:
        """PENDING -> ACTIVE。"""
        with self._lock, self._state.transaction():
            return self._transition_locked(key_id, version, KeyState.ACTIVE, now)

    def rotate(self, key_id: str, now: float, transition_seconds: float) -> KeyVersion:
        """轮转：当前 ACTIVE 进入 VERIFY_ONLY 过渡期，新版本立即 ACTIVE。"""
        with self._lock, self._state.transaction():
            self._refresh_locked(now)
            versions = self._state.keys.get(key_id)
            if versions is None:
                raise KeyError(key_id)
            current = next((v for v in versions if v.state == KeyState.ACTIVE), None)
            if current is None:
                raise IllegalTransitionError(
                    key_id, -1, KeyState.VERIFY_ONLY, KeyState.ACTIVE)
            current.state = KeyState.VERIFY_ONLY
            current.verify_only_until = now + transition_seconds
            new_kv = self._new_version(key_id, current.version + 1, now,
                                       predecessor=current.version)
            new_kv.state = KeyState.ACTIVE
            new_kv.activated_at = now
            versions.append(new_kv)
            return self._snapshot(new_kv)

    def revoke(self, key_id: str, version: int, now: float) -> KeyVersion:
        with self._lock, self._state.transaction():
            return self._transition_locked(key_id, version, KeyState.REVOKED, now)

    def transition(self, key_id: str, version: int, target: KeyState, now: float,
                   transition_seconds: float = 0.0) -> KeyVersion:
        """显式状态迁移，非法迁移抛 IllegalTransitionError。"""
        with self._lock, self._state.transaction():
            return self._transition_locked(key_id, version, target, now,
                                           transition_seconds)

    def _transition_locked(self, key_id: str, version: int, target: KeyState,
                           now: float, transition_seconds: float = 0.0) -> KeyVersion:
        """在事务内执行状态迁移（调用方须已持有事务）。"""
        kv = self._find(key_id, version)
        if kv is None:
            raise KeyError((key_id, version))
        if target not in ALLOWED_TRANSITIONS[kv.state]:
            raise IllegalTransitionError(key_id, version, kv.state, target)
        kv.state = target
        if target == KeyState.ACTIVE:
            kv.activated_at = now
        elif target == KeyState.VERIFY_ONLY:
            kv.verify_only_until = now + transition_seconds
        elif target == KeyState.REVOKED:
            kv.revoked_at = now
        return self._snapshot(kv)

    def refresh(self, now: float) -> None:
        """按当前时间推进状态：过渡期结束的 VERIFY_ONLY 自动吊销。"""
        with self._lock, self._state.transaction():
            self._refresh_locked(now)

    def _refresh_locked(self, now: float) -> None:
        for versions in self._state.keys.values():
            for kv in versions:
                if (kv.state == KeyState.VERIFY_ONLY
                        and kv.verify_only_until is not None
                        and now >= kv.verify_only_until):
                    kv.state = KeyState.REVOKED
                    kv.revoked_at = now

    # ---- 查询 ----------------------------------------------------------
    def _find(self, key_id: str, version: int) -> KeyVersion | None:
        for kv in self._state.keys.get(key_id, ()):
            if kv.version == version:
                return kv
        return None

    def get(self, key_id: str, version: int) -> KeyVersion | None:
        with self._lock:
            kv = self._find(key_id, version)
            return self._snapshot(kv) if kv else None

    def active_version(self, key_id: str) -> KeyVersion | None:
        with self._lock:
            for kv in self._state.keys.get(key_id, ()):
                if kv.state == KeyState.ACTIVE:
                    return self._snapshot(kv)
            return None

    def list_versions(self, key_id: str) -> list[KeyVersion]:
        with self._lock:
            return [self._snapshot(kv) for kv in self._state.keys.get(key_id, ())]

    @staticmethod
    def _snapshot(kv: KeyVersion) -> KeyVersion:
        return KeyVersion(**{**kv.__dict__, "public_key_pem": kv.public_key_pem,
                             "private_key_pem": kv.private_key_pem})

    # ---- 持久化（委托 StateStore） --------------------------------------
    def save(self) -> None:
        self._state.save()

    def load(self) -> None:
        self._state.load()
