"""密钥服务：把密钥生命周期、签名验签、重放防护、封存恢复串起来。

并发语义：所有判定路径共用一把可重入锁，“检查 + 状态/流水落库”在同一
临界区内完成。因此轮转与验签并发时，一个已签名请求的结论是确定的：
要么在落库前完成（通过），要么在落库后完成（重放），不会既通过又被拒绝。

验签判定顺序（失败原因因此可区分）：
    1. 版本存在        -> KEY_VERSION_NOT_FOUND
    2. 生命周期状态     -> KEY_PENDING / KEY_REVOKED / KEY_VERIFY_WINDOW_EXPIRED
    3. 时间窗          -> SKEW_TOO_OLD / SKEW_IN_FUTURE
    4. 签名            -> SIGNATURE_MISMATCH
    5. 随机数流水       -> NONCE_REPLAY（仅在以上全部通过后才记录流水）
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import logging
import secrets
import threading
import time
from typing import Callable, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from app.errors import ErrorCode, KeyServiceError
from app.keys import ALLOWED_TRANSITIONS, KeyMaterial, KeyState
from app.sealing import Seal, seal_materials, unseal_materials
from app.signing import canonical_request, sign, verify
from app.state import LocalState, StoredKey

# 允许的请求时间偏移（秒）
DEFAULT_SKEW_SECONDS = 300
# nonce 流水保留时长（秒），到期淘汰
DEFAULT_NONCE_RETENTION_SECONDS = 3600


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text, validate=True)


@dataclasses.dataclass
class SignedRequest:
    version: int
    timestamp: int
    nonce: str
    signature: bytes
    method: str
    path: str
    body: bytes
    headers: dict[str, str] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class VerifyDecision:
    accepted: bool
    error_code: Optional[str]
    reason: str


class KeyService:
    def __init__(
        self,
        state_path: str = "kms_state.json",
        clock: Optional[Callable[[], int]] = None,
        skew_seconds: int = DEFAULT_SKEW_SECONDS,
        nonce_retention_seconds: int = DEFAULT_NONCE_RETENTION_SECONDS,
    ) -> None:
        self._lock = threading.RLock()
        self.clock = clock or (lambda: int(time.time()))
        self.skew_seconds = skew_seconds
        self.nonce_retention_seconds = nonce_retention_seconds
        self.state: LocalState = LocalState.load(state_path)
        self.logger = logging.getLogger("app.service")

    # ------------------------------------------------------------------
    # 内部辅助
    # ------------------------------------------------------------------
    def _material(self, version: int) -> KeyMaterial:
        sk = self.state.keys.get(version)
        if sk is None:
            raise KeyServiceError(
                ErrorCode.KEY_VERSION_NOT_FOUND, f"密钥版本 {version} 不存在"
            )
        return KeyMaterial(
            version=sk.version,
            public_bytes=_b64d(sk.public_b64),
            private_bytes=_b64d(sk.private_b64),
            state=KeyState(sk.state),
            created_at=sk.created_at,
            verify_until=sk.verify_until,
        )

    def _current(self) -> Optional[KeyMaterial]:
        v = self.state.current_version
        if v is None:
            return None
        return self._material(v)

    def _prune(self, now: int) -> bool:
        return self.state.prune_nonces(now, self.nonce_retention_seconds) > 0

    @staticmethod
    def _derive_public(private_bytes: bytes) -> bytes:
        return (
            Ed25519PrivateKey.from_private_bytes(private_bytes)
            .public_key()
            .public_bytes(Encoding.Raw, PublicFormat.Raw)
        )

    # ------------------------------------------------------------------
    # 生命周期管理
    # ------------------------------------------------------------------
    def create_key(self) -> int:
        """生成一把 PENDING 密钥（不改变当前签名版本）。"""
        with self._lock:
            now = self.clock()
            dirty = self._prune(now)
            version = (max(self.state.keys, default=0) + 1)
            private_key = Ed25519PrivateKey.generate()
            private_bytes = private_key.private_bytes_raw()
            public_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            self.state.put_key(
                version=version,
                public_bytes=public_bytes,
                private_bytes=private_bytes,
                state=KeyState.PENDING.value,
                created_at=now,
                verify_until=None,
            )
            self.state.save()
            self.logger.info(
                "create_key 输入=<无> 判定=生成版本 v%d 状态 PENDING 指纹=%s%s",
                version,
                self._material(version).fingerprint(),
                ("（同时淘汰过期 nonce）" if dirty else ""),
            )
            return version

    def activate(self, version: int) -> None:
        """PENDING -> ACTIVE，设为当前签名版本；已有 ACTIVE 时拒绝。"""
        with self._lock:
            key = self._material(version)
            cur = self._current()
            if cur is not None and cur.state is KeyState.ACTIVE and cur.version != version:
                raise KeyServiceError(
                    ErrorCode.ILLEGAL_TRANSITION,
                    f"版本 {cur.version} 已处于 ACTIVE，请使用轮转而非直接启用",
                )
            self.transition(version, KeyState.ACTIVE)

    def rotate(self, transition_seconds: int = 86400) -> int:
        """原子轮转：新版本 ACTIVE；旧 ACTIVE -> VERIFY_ONLY(now+过渡期)。"""
        with self._lock:
            now = self.clock()
            dirty = self._prune(now)
            old_version = self.state.current_version
            new_version = (max(self.state.keys, default=0) + 1)
            private_key = Ed25519PrivateKey.generate()
            private_bytes = private_key.private_bytes_raw()
            public_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            self.state.put_key(
                version=new_version,
                public_bytes=public_bytes,
                private_bytes=private_bytes,
                state=KeyState.ACTIVE.value,
                created_at=now,
                verify_until=None,
            )
            if old_version is not None:
                old = self._material(old_version)
                if old.state is not KeyState.ACTIVE:
                    # 状态关系被破坏：不静默处理
                    raise KeyServiceError(
                        ErrorCode.ILLEGAL_TRANSITION,
                        f"当前版本 {old_version} 状态为 {old.state.value}，无法轮转",
                    )
                sk = self.state.keys[old_version]
                sk.state = KeyState.VERIFY_ONLY.value
                sk.verify_until = now + transition_seconds
            self.state.current_version = new_version
            self.state.save()
            self.logger.info(
                "rotate 输入=transition_seconds=%d 判定=v%s ACTIVE->VERIFY_ONLY(截止=%s)；"
                "新版本 v%d ACTIVE 指纹=%s%s",
                transition_seconds,
                old_version if old_version is not None else "-",
                now + transition_seconds if old_version is not None else "-",
                new_version,
                self._material(new_version).fingerprint(),
                ("（同时淘汰过期 nonce）" if dirty else ""),
            )
            return new_version

    def transition(
        self,
        version: int,
        target: KeyState,
        verify_until: Optional[int] = None,
    ) -> None:
        """执行一次显式状态迁移；非法迁移以 ILLEGAL_TRANSITION 拒绝。"""
        with self._lock:
            key = self._material(version)
            if target not in ALLOWED_TRANSITIONS[key.state]:
                raise KeyServiceError(
                    ErrorCode.ILLEGAL_TRANSITION,
                    f"非法迁移：版本 {version} {key.state.value} -> {target.value}",
                )
            if target is KeyState.ACTIVE:
                cur = self._current()
                if cur is not None and cur.version != version and cur.state is KeyState.ACTIVE:
                    raise KeyServiceError(
                        ErrorCode.ILLEGAL_TRANSITION,
                        f"版本 {cur.version} 已处于 ACTIVE，不能并存第二个 ACTIVE 版本",
                    )
                self.state.current_version = version
            sk = self.state.keys[version]
            sk.state = target.value
            if target is KeyState.VERIFY_ONLY:
                sk.verify_until = verify_until if verify_until is not None else sk.verify_until
            if target is KeyState.REVOKED:
                sk.verify_until = None
                if self.state.current_version == version:
                    self.state.current_version = None
            self.state.save()
            self.logger.info(
                "transition 输入=v%d -> %s verify_until=%s 判定=迁移合法并已落库",
                version,
                target.value,
                sk.verify_until,
            )

    def revoke(self, version: int) -> None:
        """吊销（任意非终态 -> REVOKED）；重复吊销以 ILLEGAL_TRANSITION 拒绝。"""
        self.transition(version, KeyState.REVOKED)

    # ------------------------------------------------------------------
    # 签名与验签
    # ------------------------------------------------------------------
    def _canonical(self, req: "SignedRequest") -> bytes:
        return canonical_request(
            req.method,
            req.path,
            req.body,
            req.headers,
            req.version,
            req.timestamp,
            req.nonce,
        )

    def sign_request(
        self,
        method: str,
        path: str,
        body: bytes,
        headers: Optional[dict[str, str]] = None,
    ) -> SignedRequest:
        with self._lock:
            now = self.clock()
            dirty = self._prune(now)
            key = self._current()
            if key is None or key.state is not KeyState.ACTIVE:
                raise KeyServiceError(
                    ErrorCode.NO_ACTIVE_KEY,
                    "当前没有处于 ACTIVE 的密钥版本可用于签名",
                )
            nonce = secrets.token_urlsafe(16)
            req = SignedRequest(
                version=key.version,
                timestamp=now,
                nonce=nonce,
                signature=b"",
                method=method.upper(),
                path=path,
                body=body,
                headers=dict(headers or {}),
            )
            message = self._canonical(req)
            req.signature = sign(key.private_bytes, message)
            self.logger.info(
                "sign_request 输入=method=%s path=%s body_len=%d nonce=%s "
                "判定依据=当前版本 v%d 为 ACTIVE，时间戳=%d，使用其私钥签名 sig=%s...%s",
                req.method,
                req.path,
                len(req.body),
                nonce,
                key.version,
                now,
                req.signature.hex()[:16],
                ("（同时淘汰过期 nonce）" if dirty else ""),
            )
            return req

    def verify_request(self, req: "SignedRequest") -> VerifyDecision:
        with self._lock:
            now = self.clock()
            dirty = self._prune(now)
            self.logger.info(
                "verify_request 输入=v%d ts=%d nonce=%s method=%s path=%s body=%r "
                "headers=%r sig=%s...",
                req.version,
                req.timestamp,
                req.nonce,
                req.method,
                req.path,
                req.body,
                req.headers,
                req.signature.hex()[:16],
            )

            def reject(code: ErrorCode, basis: str) -> VerifyDecision:
                if dirty:
                    self.state.save()
                self.logger.info("verify_request 判定=拒绝 原因=%s 依据=%s", code.value, basis)
                return VerifyDecision(False, code.value, basis)

            # 1) 版本存在性
            sk = self.state.keys.get(req.version)
            if sk is None:
                return reject(
                    ErrorCode.KEY_VERSION_NOT_FOUND,
                    f"版本 {req.version} 在本地状态中不存在",
                )

            # 2) 生命周期
            state = KeyState(sk.state)
            if state is KeyState.REVOKED:
                return reject(
                    ErrorCode.KEY_REVOKED,
                    f"版本 {req.version} 已吊销（REVOKED 为终态），拒绝任何使用",
                )
            if state is KeyState.PENDING:
                return reject(
                    ErrorCode.KEY_PENDING,
                    f"版本 {req.version} 尚为 PENDING，未启用，不可验签",
                )
            if state is KeyState.VERIFY_ONLY and sk.verify_until is not None and now > sk.verify_until:
                return reject(
                    ErrorCode.KEY_VERIFY_WINDOW_EXPIRED,
                    f"版本 {req.version} 的只验签过渡期已于 {sk.verify_until} 截止"
                    f"（当前 {now}），拒绝验签",
                )

            # 3) 时间窗
            if req.timestamp < now - self.skew_seconds:
                return reject(
                    ErrorCode.SKEW_TOO_OLD,
                    f"请求时间 {req.timestamp} 早于允许下界 "
                    f"{now - self.skew_seconds}（窗口 ±{self.skew_seconds}s）",
                )
            if req.timestamp > now + self.skew_seconds:
                return reject(
                    ErrorCode.SKEW_IN_FUTURE,
                    f"请求时间 {req.timestamp} 晚于允许上界 "
                    f"{now + self.skew_seconds}（窗口 ±{self.skew_seconds}s）",
                )

            # 4) 签名
            message = self._canonical(req)
            if not verify(_b64d(sk.public_b64), message, req.signature):
                return reject(
                    ErrorCode.SIGNATURE_MISMATCH,
                    f"规范化串经版本 {req.version} 公钥验签失败（方法/负载/nonce/时间戳任一不符）",
                )

            # 5) nonce 重放（只有前四步全部通过才记录流水）
            if req.nonce in self.state.nonces:
                first = self.state.nonces[req.nonce]
                return reject(
                    ErrorCode.NONCE_REPLAY,
                    f"nonce={req.nonce} 已于 {first} 使用过，重复请求判定为重放",
                )
            self.state.nonces[req.nonce] = now
            self.state.save()
            self.logger.info(
                "verify_request 判定=接受 依据=版本状态=%s 时间窗通过 签名匹配 nonce 首次出现(已落库)%s",
                state.value,
                "；并已淘汰过期流水" if dirty else "",
            )
            return VerifyDecision(True, None, "时间窗内、签名匹配、nonce 首次出现")

    # ------------------------------------------------------------------
    # 封存与恢复
    # ------------------------------------------------------------------
    def export_sealed(self, password: str) -> Seal:
        """把全部版本的私钥材料封存入口令保护的封套。"""
        with self._lock:
            materials = {v: _b64d(sk.private_b64) for v, sk in self.state.keys.items()}
            context_keys = []
            for v in sorted(self.state.keys):
                km = self._material(v)
                context_keys.append(
                    {
                        "version": v,
                        "state": km.state.value,
                        "created_at": km.created_at,
                        "verify_until": km.verify_until,
                        "public_b64": _b64e(km.public_bytes),
                        "fingerprint": km.fingerprint(),
                    }
                )
            metadata = {
                "current_version": self.state.current_version,
                "exported_at": self.clock(),
                "keys": context_keys,
            }
            seal = seal_materials(materials, password, metadata)
            self.logger.info(
                "export_sealed 输入=口令(***) 判定=已封存 %d 个版本 当前版本=%s",
                len(materials),
                self.state.current_version,
            )
            return seal

    def restore_sealed(self, seal: Seal, password: str) -> None:
        """恢复封套。成功则整体替换版本集合；任何校验失败都不改动本地状态。"""
        with self._lock:
            metadata, materials = unseal_materials(seal, password)  # BAD_PASSWORD / SEAL_TAMPERED

            # --- 在触碰本地状态前完成全部校验（失败不留半成品） ---
            try:
                keys_meta = metadata["keys"]
                current_version = metadata["current_version"]
                meta_versions = {int(k["version"]) for k in keys_meta}
            except (KeyError, ValueError, TypeError) as exc:
                raise KeyServiceError(
                    ErrorCode.INCOMPLETE_VERSION_SET, "封套元数据缺少版本关系字段"
                ) from exc

            if set(materials) != meta_versions or not materials:
                raise KeyServiceError(
                    ErrorCode.INCOMPLETE_VERSION_SET,
                    f"版本关系不完整：私钥版本 {sorted(materials)} 与元数据版本 "
                    f"{sorted(meta_versions)} 不一致或为空",
                )
            if current_version is not None and current_version not in meta_versions:
                raise KeyServiceError(
                    ErrorCode.INCOMPLETE_VERSION_SET,
                    f"current_version={current_version} 不在封存版本集合内",
                )

            rebuilt: dict[int, object] = {}
            actives: list[int] = []
            for k in keys_meta:
                v = int(k["version"])
                try:
                    state = KeyState(k["state"])
                    public_b64 = k["public_b64"]
                    created_at = int(k["created_at"])
                    verify_until = k.get("verify_until")
                    if verify_until is not None:
                        verify_until = int(verify_until)
                except (KeyError, ValueError, TypeError) as exc:
                    raise KeyServiceError(
                        ErrorCode.INCOMPLETE_VERSION_SET, f"版本 {v} 元数据不完整"
                    ) from exc
                if state is KeyState.ACTIVE:
                    actives.append(v)
                derived_pub = self._derive_public(materials[v])
                if _b64e(derived_pub) != public_b64:
                    raise KeyServiceError(
                        ErrorCode.FINGERPRINT_MISMATCH,
                        f"版本 {v} 私钥导出的公钥与封存公钥不一致，指纹不可复现",
                    )
                fp = hashlib.sha256(derived_pub).hexdigest()
                if k.get("fingerprint") != fp:
                    raise KeyServiceError(
                        ErrorCode.FINGERPRINT_MISMATCH,
                        f"版本 {v} 封存指纹 {k.get('fingerprint')} 与复算指纹 {fp} 不一致",
                    )
                rebuilt[v] = StoredKey(
                    version=v,
                    public_b64=public_b64,
                    private_b64=_b64e(materials[v]),
                    state=state.value,
                    created_at=created_at,
                    verify_until=verify_until,
                )

            if current_version is None and actives:
                raise KeyServiceError(
                    ErrorCode.INCOMPLETE_VERSION_SET,
                    "存在 ACTIVE 版本但缺少 current_version 关系",
                )
            if current_version is not None and (
                len(actives) != 1 or actives[0] != current_version
            ):
                raise KeyServiceError(
                    ErrorCode.INCOMPLETE_VERSION_SET,
                    f"版本关系不完整：current_version={current_version}，"
                    f"ACTIVE 版本={actives}，关系必须唯一对应",
                )

            # --- 全部通过后整体替换（nonce 流水保留，重放防护不被恢复绕过） ---
            self.state.keys = rebuilt
            self.state.current_version = current_version
            self.state.save()
            self.logger.info(
                "restore_sealed 输入=口令(***) 判定=口令与密文校验通过，指纹全部可复现，"
                "已整体恢复 %d 个版本 当前=%s",
                len(rebuilt),
                current_version,
            )

    # ------------------------------------------------------------------
    # 只读视图
    # ------------------------------------------------------------------
    def get_key(self, version: int) -> KeyMaterial:
        with self._lock:
            return self._material(version)

    def list_versions(self) -> list[dict[str, object]]:
        with self._lock:
            cur = self.state.current_version
            result = []
            for v in sorted(self.state.keys):
                km = self._material(v)
                result.append(
                    {
                        "version": v,
                        "state": km.state.value,
                        "current": v == cur,
                        "created_at": km.created_at,
                        "verify_until": km.verify_until,
                        "fingerprint": km.fingerprint(),
                    }
                )
            return result
