"""密钥多版本与生命周期管理；密钥状态与请求流水共用同一份本地状态文件。

持久化与并发模型：
- 状态文件为单个 JSON，密钥版本与 nonce 流水一起序列化、原子替换落盘，
  二者要么同时生效、要么都不生效，重启后不会对不上。
- 跨进程通过同目录下 ``<state>.lock`` 文件的 ``flock`` 互斥；拿到锁后先
  重读磁盘，使其它进程刚刚提交的密钥变化与流水对本进程立即可见。
- 旧版状态文件（无 format 字段的纯密钥映射）可直接读取，首次保存时自动
  升级为新格式，无需清空状态或人工迁移。
"""
from __future__ import annotations

import base64
import contextlib
import fcntl
import json
import os
import threading

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .journal import NonceJournal
from .models import ALLOWED_TRANSITIONS, JournalOutcome, KeyState, KeyVersion, NonceRecord

STATE_FORMAT = "kms-state-v2"


class IllegalTransitionError(Exception):
    """非法状态迁移。"""

    def __init__(self, key_id: str, version: int, src: KeyState, dst: KeyState) -> None:
        self.key_id, self.version, self.src, self.dst = key_id, version, src, dst
        super().__init__(
            f"illegal transition {src.value}->{dst.value} for {key_id} v{version}")


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(text: str) -> str | bytes:
    return base64.b64decode(text.encode("ascii"))


class KeyStore:
    """管理密钥版本链、状态迁移与 nonce 流水的统一持久化。"""

    def __init__(self, state_path: str = "keystore_state.json",
                 retention_seconds: float = 300.0,
                 nonce_capacity: int = 1_000_000) -> None:
        self._lock = threading.RLock()
        self._state_path = state_path
        self._keys: dict[str, list[KeyVersion]] = {}
        self.journal = NonceJournal(retention_seconds, nonce_capacity)
        # flock 句柄：与状态文件分离，避免 os.replace 更换 inode 后锁失效
        self._lock_fd = open(state_path + ".lock", "a+b")
        self._load_locked()

    def bind_lock(self, lock: threading.RLock) -> None:
        """与服务层共用同一把线程锁。"""
        self._lock = lock
        self.journal.bind_lock(lock)

    @contextlib.contextmanager
    def exclusive(self):
        """跨进程互斥段：加文件锁后重读磁盘，保证看到其它进程的最新提交。"""
        with self._lock:
            fcntl.flock(self._lock_fd, fcntl.LOCK_EX)
            try:
                self._load_locked()
                yield
            finally:
                fcntl.flock(self._lock_fd, fcntl.LOCK_UN)

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

    # ---- 生命周期（调用方须持有 exclusive 段） ---------------------------
    def create_key(self, key_id: str, now: float) -> KeyVersion:
        """生成首个版本（PENDING）。key_id 已存在则报错。"""
        if key_id in self._keys:
            raise ValueError(f"key {key_id!r} already exists")
        kv = self._new_version(key_id, 1, now, predecessor=None)
        self._keys[key_id] = [kv]
        self.save()
        return self._snapshot(kv)

    def activate(self, key_id: str, version: int, now: float) -> KeyVersion:
        """PENDING -> ACTIVE。"""
        return self._transition_locked(key_id, version, KeyState.ACTIVE, now)

    def rotate(self, key_id: str, now: float, transition_seconds: float) -> KeyVersion:
        """轮转：当前 ACTIVE 进入 VERIFY_ONLY 过渡期，新版本立即 ACTIVE。"""
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
        return self._transition_locked(key_id, version, KeyState.REVOKED, now)

    def transition(self, key_id: str, version: int, target: KeyState, now: float,
                   transition_seconds: float = 0.0) -> KeyVersion:
        """显式状态迁移，非法迁移抛 IllegalTransitionError。"""
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
        kv = self._find(key_id, version)
        return self._snapshot(kv) if kv else None

    def active_version(self, key_id: str) -> KeyVersion | None:
        for kv in self._keys.get(key_id, ()):
            if kv.state == KeyState.ACTIVE:
                return self._snapshot(kv)
        return None

    def list_versions(self, key_id: str) -> list[KeyVersion]:
        return [self._snapshot(kv) for kv in self._keys.get(key_id, ())]

    def all_versions(self) -> list[KeyVersion]:
        return [self._snapshot(kv)
                for key_id in sorted(self._keys)
                for kv in self._keys[key_id]]

    @staticmethod
    def _snapshot(kv: KeyVersion) -> KeyVersion:
        return KeyVersion(**{**kv.__dict__, "public_key_pem": kv.public_key_pem,
                             "private_key_pem": kv.private_key_pem})

    # ---- 持久化 --------------------------------------------------------
    def save(self) -> None:
        """密钥版本与 nonce 流水一次性原子写盘（调用方持锁）。"""
        keys = {}
        for key_id, versions in self._keys.items():
            keys[key_id] = [
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
        nonces = [
            {
                "seq": r.seq,
                "key_id": r.key_id,
                "version": r.version,
                "nonce": r.nonce,
                "timestamp": r.timestamp,
                "recorded_at": r.recorded_at,
                "outcome": r.outcome.value,
                "basis": r.basis,
            }
            for r in self.journal.dump_state()
        ]
        data = {"format": STATE_FORMAT, "keys": keys,
                "nonces": nonces, "nonce_seq": self.journal.next_seq}
        tmp = self._state_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self._state_path)

    def load(self) -> None:
        """显式重读磁盘（初始化时已自动加载一次）。"""
        with self._lock:
            self._load_locked()

    def _load_locked(self) -> None:
        """从磁盘重读全部状态；旧格式（纯密钥映射）自动兼容。"""
        if not os.path.exists(self._state_path):
            self._keys = {}
            self.journal.load_state([])
            return
        with open(self._state_path, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict) and data.get("format") == STATE_FORMAT:
            raw_keys = data.get("keys", {})
            records = [self._record_from_dict(it) for it in data.get("nonces", [])]
            self.journal.load_state(records, next_seq=int(data.get("nonce_seq", 0)))
        else:
            # 旧版状态文件：顶层即 key_id -> 版本列表
            raw_keys = data
            self.journal.load_state([])
        keys: dict[str, list[KeyVersion]] = {}
        for key_id, items in raw_keys.items():
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

    @staticmethod
    def _record_from_dict(item: dict) -> NonceRecord:
        return NonceRecord(
            seq=int(item["seq"]),
            key_id=item["key_id"],
            version=int(item["version"]),
            nonce=item["nonce"],
            timestamp=float(item["timestamp"]),
            recorded_at=float(item["recorded_at"]),
            outcome=JournalOutcome(item["outcome"]),
            basis=item.get("basis", ""),
        )
