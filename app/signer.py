"""请求签名、验签与重放防护（流水由 RequestLedger 持久化）。"""
from __future__ import annotations

import threading
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .keystore import KeyStore
from .ledger import CapacityExceededError, RequestLedger
from .models import FailureReason, KeyState, LedgerRecord, SignedRequest, VerifyResult


def _fail(reason: FailureReason, detail: str) -> VerifyResult:
    return VerifyResult(ok=False, reason=reason, detail=detail)


class Signer:
    """签名与验签，结论含可区分失败原因。

    验签通过的请求把 nonce 记入 RequestLedger（随状态文件落盘），
    重启或多进程下重复判定一致；伪造签名的请求不占用 nonce。
    """

    def __init__(self, store: KeyStore, window_seconds: float,
                 ledger: RequestLedger) -> None:
        self._store = store
        self._window = window_seconds
        self._ledger = ledger
        # 外部可注入同一把锁，保证“轮转与验签”在服务层面串行化
        self._lock = threading.RLock()

    @property
    def nonces(self) -> RequestLedger:
        """已受理请求的流水（重放判定集合）。"""
        return self._ledger

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
            priv = serialization.load_pem_private_key(kv.private_key_pem,
                                                      password=None)
            assert isinstance(priv, Ed25519PrivateKey)
            req = SignedRequest(method=method.upper(), payload=payload,
                                key_id=key_id, version=kv.version,
                                timestamp=now, nonce=nonce)
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
            if (kv.state == KeyState.VERIFY_ONLY
                    and kv.verify_only_until is not None
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

            # 4) 重放：仅合法签名才记录 nonce；容量满则明确拒绝
            record = LedgerRecord(
                nonce=req.nonce, key_id=req.key_id, version=req.version,
                request_timestamp=req.timestamp, decided_at=now,
                decision="accepted",
                basis=(f"key_state={kv.state.value}; timestamp_in_window; "
                       f"signature_ok; nonce_fresh"))
            try:
                fresh = self._ledger.check_and_record(record, now)
            except CapacityExceededError as exc:
                return _fail(FailureReason.LEDGER_CAPACITY_EXCEEDED, str(exc))
            if not fresh:
                return _fail(FailureReason.NONCE_REUSED,
                             f"nonce {req.nonce!r} already used")

            return VerifyResult(ok=True,
                                detail=f"accepted with {req.key_id} v{req.version}")
