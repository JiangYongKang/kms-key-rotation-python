"""密钥多版本与生命周期管理，本地 JSON 状态持久化。"""
from __future__ import annotations

import base64
import json
import os
import threading

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .models import ALLOWED_TRANSITIONS, KeyState, KeyVersion


class IllegalTransitionError(Exception):
    """非法状态迁移。"""

    def __init__(self, key_id: str, version: int, src: KeyState, dst: KeyState) -> None:
        self.key_id, self.version, self.src, self.dst = key_id, version, src, dst
        super().__init__(
            f"illegal transition {src.value}->{dst.value} for {key_id} v{version}")


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


class KeyStore:
    """管理密钥版本链与状态迁移，状态落盘到本地 JSON 文件。"""

    def __init__(self, state_path: str = "keystore_state.json") -> None:
        self._lock = threading.RLock()
        self._state_path = state_path
        self._keys: dict[str, list[KeyVersion]] = {}

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

    # ---- 生命周期 ------------------------------------------------------
    def create_key(self, key_id: str, now: float) -> KeyVersion:
        """生成首个版本（PENDING）。key_id 已存在则报错。"""
        with self._lock:
            if key_id in self._keys:
                raise ValueError(f"key {key_id!r} already exists")
            kv = self._new_version(key_id, 1, now, predecessor=None)
            self._keys[key_id] = [kv]
            self.save()
            return self._snapshot(kv)

    def activate(self, key_id: str, version: int, now: float) -> KeyVersion:
        """PENDING -> ACTIVE。"""
        with self._lock:
            return self._transition_locked(key_id, version, KeyState.ACTIVE, now)

    def rotate(self, key_id: str, now: float, transition_seconds: float) -> KeyVersion:
        """轮转：当前 ACTIVE 进入 VERIFY_ONLY 过渡期，新版本立即 ACTIVE。"""
        with self._lock:
            self.refresh(now)
            versions = self._keys.get(key_id)
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
            self.save()
            return self._snapshot(new_kv)

    def revoke(self, key_id: str, version: int, now: float) -> KeyVersion:
        with self._lock:
            return self._transition_locked(key_id, version, KeyState.REVOKED, now)

    def transition(self, key_id: str, version: int, target: KeyState, now: float,
                   transition_seconds: float = 0.0) -> KeyVersion:
        """显式状态迁移，非法迁移抛 IllegalTransitionError。"""
        with self._lock:
            return self._transition_locked(key_id, version, target, now,
                                           transition_seconds)

    def _transition_locked(self, key_id: str, version: int, target: KeyState,
                           now: float, transition_seconds: float = 0.0) -> KeyVersion:
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
        self.save()
        return self._snapshot(kv)

    def refresh(self, now: float) -> None:
        """按当前时间推进状态：过渡期结束的 VERIFY_ONLY 自动吊销。"""
        with self._lock:
            changed = False
            for versions in self._keys.values():
                for kv in versions:
                    if (kv.state == KeyState.VERIFY_ONLY
                            and kv.verify_only_until is not None
                            and now >= kv.verify_only_until):
                        kv.state = KeyState.REVOKED
                        kv.revoked_at = now
                        changed = True
            if changed:
                self.save()

    # ---- 查询 ----------------------------------------------------------
    def _find(self, key_id: str, version: int) -> KeyVersion | None:
        for kv in self._keys.get(key_id, ()):
            if kv.version == version:
                return kv
        return None

    def get(self, key_id: str, version: int) -> KeyVersion | None:
        with self._lock:
            kv = self._find(key_id, version)
            return self._snapshot(kv) if kv else None

    def active_version(self, key_id: str) -> KeyVersion | None:
        with self._lock:
            for kv in self._keys.get(key_id, ()):
                if kv.state == KeyState.ACTIVE:
                    return self._snapshot(kv)
            return None

    def list_versions(self, key_id: str) -> list[KeyVersion]:
        with self._lock:
            return [self._snapshot(kv) for kv in self._keys.get(key_id, ())]

    @staticmethod
    def _snapshot(kv: KeyVersion) -> KeyVersion:
        return KeyVersion(**{**kv.__dict__, "public_key_pem": kv.public_key_pem,
                             "private_key_pem": kv.private_key_pem})

    # ---- 持久化 --------------------------------------------------------
    def save(self) -> None:
        with self._lock:
            data = {}
            for key_id, versions in self._keys.items():
                data[key_id] = [
                    {
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
                    for v in versions
                ]
            tmp = self._state_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, sort_keys=True)
            os.replace(tmp, self._state_path)

    def load(self) -> None:
        with self._lock:
            if not os.path.exists(self._state_path):
                self._keys = {}
                return
            with open(self._state_path, encoding="utf-8") as f:
                data = json.load(f)
            keys: dict[str, list[KeyVersion]] = {}
            for key_id, items in data.items():
                keys[key_id] = [
                    KeyVersion(
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
                    for item in items
                ]
            self._keys = keys
