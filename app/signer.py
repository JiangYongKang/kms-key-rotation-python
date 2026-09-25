"""请求签名、验签与重放防护（随机数按时间淘汰）。"""
from __future__ import annotations

import threading
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .keystore import KeyStore
from .models import FailureReason, KeyState, SignedRequest, VerifyResult


class NonceStore:
    """随机数流水：记录已见 nonce，按时间窗淘汰，避免无界增长。"""

    def __init__(self, window_seconds: float) -> None:
        self._lock = threading.Lock()
        self._window = window_seconds
        self._seen: dict[str, float] = {}

    def check_and_record(self, nonce: str, now: float) -> bool:
        """nonce 未见过则记录并返回 True，重复返回 False；同时淘汰过期记录。"""
        with self._lock:
            cutoff = now - self._window
            stale = [n for n, ts in self._seen.items() if ts < cutoff]
            for n in stale:
                del self._seen[n]
            if nonce in self._seen:
                return False
            self._seen[nonce] = now
            return True

    def __len__(self) -> int:
        with self._lock:
            return len(self._seen)


def _fail(reason: FailureReason, detail: str) -> VerifyResult:
    return VerifyResult(ok=False, reason=reason, detail=detail)


class Signer:
    """签名与验签，结论含可区分失败原因。"""

    def __init__(self, store: KeyStore, window_seconds: float = 300.0) -> None:
        self._store = store
        self._window = window_seconds
        self._nonces = NonceStore(window_seconds)
        # 外部可注入同一把锁，保证“轮转与验签”在服务层面串行化
        self._lock = threading.RLock()

    @property
    def nonces(self) -> NonceStore:
        return self._nonces

    def bind_lock(self, lock: threading.RLock) -> None:
        self._lock = lock

    def sign(self, key_id: str, method: str, payload: bytes, now: float,
             nonce: str | None = None) -> SignedRequest | VerifyResult:
        """用当前 ACTIVE 版本签名；密钥不可签名时返回失败结论。"""
        with self._lock:
            kv = self._store.active_version(key_id)
            if kv is None:
                versions = self._store.list_versions(key_id)
                if not versions:
                    return _fail(FailureReason.KEY_NOT_FOUND,
                                 f"key {key_id!r} not found")
                latest = versions[-1]
                if latest.state == KeyState.PENDING:
                    return _fail(FailureReason.KEY_PENDING,
                                 f"{key_id} v{latest.version} is pending")
                if latest.state == KeyState.VERIFY_ONLY:
                    return _fail(FailureReason.KEY_VERIFY_ONLY,
                                 f"{key_id} v{latest.version} is verify-only")
                return _fail(FailureReason.KEY_REVOKED,
                             f"{key_id} v{latest.version} is revoked")
            if nonce is None:
                nonce = uuid.uuid4().hex
            priv = serialization.load_pem_private_key(kv.private_key_pem, password=None)
            assert isinstance(priv, Ed25519PrivateKey)
            req = SignedRequest(method=method.upper(), payload=payload, key_id=key_id,
                                version=kv.version, timestamp=now, nonce=nonce)
            req.signature = priv.sign(req.canonical_bytes())
            return req

    def verify(self, req: SignedRequest, now: float) -> VerifyResult:
        """按固定顺序检查：密钥状态 -> 时间窗 -> 签名 -> nonce 重放。"""
        with self._lock:
            kv = self._store.get(req.key_id, req.version)
            if kv is None:
                return _fail(FailureReason.KEY_NOT_FOUND,
                             f"{req.key_id} v{req.version} not found")

            # 1) 密钥状态与生命周期
            if kv.state == KeyState.REVOKED:
                return _fail(FailureReason.KEY_REVOKED,
                             f"{req.key_id} v{req.version} revoked at {kv.revoked_at}")
            if kv.state == KeyState.PENDING:
                return _fail(FailureReason.KEY_PENDING,
                             f"{req.key_id} v{req.version} not active yet")
            if kv.state == KeyState.VERIFY_ONLY:
                if (kv.verify_only_until is not None
                        and now >= kv.verify_only_until):
                    return _fail(FailureReason.TRANSITION_EXPIRED,
                                 f"transition window ended at {kv.verify_only_until}"
                                 f" (now={now})")

            # 2) 时间窗
            drift = now - req.timestamp
            if abs(drift) > self._window:
                return _fail(FailureReason.TIMESTAMP_OUT_OF_WINDOW,
                             f"drift={drift:+.3f}s exceeds window={self._window}s")

            # 3) 签名匹配（先验签，避免伪造请求污染 nonce 流水）
            try:
                pub = serialization.load_pem_public_key(kv.public_key_pem)
                assert isinstance(pub, Ed25519PublicKey)
                pub.verify(req.signature, req.canonical_bytes())
            except (InvalidSignature, ValueError):
                return _fail(FailureReason.SIGNATURE_MISMATCH,
                             "signature does not verify against canonical request")

            # 4) 重放：仅合法签名才记录 nonce
            if not self._nonces.check_and_record(req.nonce, now):
                return _fail(FailureReason.NONCE_REUSED,
                             f"nonce {req.nonce!r} already used")

            return VerifyResult(ok=True,
                                detail=f"accepted with {req.key_id} v{req.version}")
