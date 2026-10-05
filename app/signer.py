"""请求签名、验签与重放防护（随机数流水带保留期与容量上限）。"""
from __future__ import annotations

import logging
import threading
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .journal import NonceJournal, NonceLogFull
from .keystore import KeyStore
from .models import FailureReason, JournalOutcome, KeyState, SignedRequest, VerifyResult

log = logging.getLogger("kms.signer")


def _fail(reason: FailureReason, detail: str) -> VerifyResult:
    return VerifyResult(ok=False, reason=reason, detail=detail)


class Signer:
    """签名与验签，结论含可区分失败原因。"""

    def __init__(self, store: KeyStore, window_seconds: float = 300.0) -> None:
        self._store = store
        self._window = window_seconds
        # 外部可注入同一把锁，保证“轮转与验签”在服务层面串行化
        self._lock = threading.RLock()

    @property
    def nonces(self) -> NonceJournal:
        """历史接口名保留：即持久化的请求随机数流水。"""
        return self._store.journal

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
            log.info("sign input: key=%s v%s method=%s nonce=%s ts=%.3f "
                     "payload_bytes=%d -> signed",
                     key_id, kv.version, req.method, nonce, now, len(payload))
            return req

    def verify(self, req: SignedRequest, now: float) -> VerifyResult:
        """按固定顺序检查：密钥状态 -> 时间窗 -> 签名 -> nonce 重放/容量。"""
        with self._lock:
            log.info("verify input: key=%s v%s method=%s nonce=%s "
                     "ts=%.3f now=%.3f payload_bytes=%d",
                     req.key_id, req.version, req.method, req.nonce,
                     req.timestamp, now, len(req.payload))
            kv = self._store.get(req.key_id, req.version)
            if kv is None:
                return self._reject(FailureReason.KEY_NOT_FOUND,
                                    f"{req.key_id} v{req.version} not found")

            # 1) 密钥状态与生命周期
            if kv.state == KeyState.REVOKED:
                return self._reject(
                    FailureReason.KEY_REVOKED,
                    f"{req.key_id} v{req.version} revoked at {kv.revoked_at}")
            if kv.state == KeyState.PENDING:
                return self._reject(
                    FailureReason.KEY_PENDING,
                    f"{req.key_id} v{req.version} not active yet")
            if kv.state == KeyState.VERIFY_ONLY:
                if (kv.verify_only_until is not None
                        and now >= kv.verify_only_until):
                    return self._reject(
                        FailureReason.TRANSITION_EXPIRED,
                        f"transition window ended at {kv.verify_only_until} "
                        f"(now={now})")

            # 2) 时间窗
            drift = now - req.timestamp
            if abs(drift) > self._window:
                return self._reject(
                    FailureReason.TIMESTAMP_OUT_OF_WINDOW,
                    f"drift={drift:+.3f}s exceeds window={self._window}s")

            # 3) 签名匹配（先验签，避免伪造请求污染 nonce 流水）
            try:
                pub = serialization.load_pem_public_key(kv.public_key_pem)
                assert isinstance(pub, Ed25519PublicKey)
                pub.verify(req.signature, req.canonical_bytes())
            except (InvalidSignature, ValueError):
                return self._reject(
                    FailureReason.SIGNATURE_MISMATCH,
                    "signature does not verify against canonical request")

            # 4) 重放 / 容量：仅合法签名才进入流水判定
            try:
                rec = self._store.journal.judge(
                    req.key_id, req.version, req.nonce, req.timestamp, now)
            except NonceLogFull as exc:
                return self._reject(
                    FailureReason.NONCE_LOG_FULL,
                    f"request refused: {exc}; no stale record is evictable")
            # 密钥与流水在同一次原子写盘里一起生效
            self._store.save()
            if rec.outcome == JournalOutcome.REPLAYED:
                return self._reject(FailureReason.NONCE_REUSED, rec.basis)
            log.info("verify basis: %s", rec.basis)
            return VerifyResult(ok=True, detail=f"accepted with "
                                                f"{req.key_id} v{req.version}")

    @staticmethod
    def _reject(reason: FailureReason, basis: str) -> VerifyResult:
        log.info("verify basis: reject reason=%s detail=%s", reason.value, basis)
        return _fail(reason, basis)
