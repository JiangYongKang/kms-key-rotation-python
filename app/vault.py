"""密钥材料封存与恢复：口令派生密钥加密导出，防篡改。"""
from __future__ import annotations

import base64
import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .models import KeyState, KeyVersion

# 口令派生参数（公开、可复现；见 README）
KDF_ALGORITHM = "PBKDF2-HMAC-SHA256"
KDF_ITERATIONS = 200_000
SALT_BYTES = 16
NONCE_BYTES = 12
ARCHIVE_FORMAT = "kms-sealed-v1"


class VaultError(Exception):
    """解封失败基类。"""


class WrongPassphraseError(VaultError):
    """口令错误或密文被篡改（AEAD 认证失败，不泄漏部分明文）。"""


class CorruptArchiveError(VaultError):
    """归档结构损坏或版本关系不完整。"""


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def _derive_key(passphrase: str, salt: bytes, iterations: int) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                     iterations=iterations)
    return kdf.derive(passphrase.encode("utf-8"))


def _version_to_dict(v: KeyVersion) -> dict:
    return {
        "key_id": v.key_id,
        "version": v.version,
        "state": v.state.value,
        "public_key_pem": _b64e(v.public_key_pem),
        "private_key_pem": _b64e(v.private_key_pem) if v.private_key_pem else None,
        "created_at": v.created_at,
        "activated_at": v.activated_at,
        "verify_only_until": v.verify_only_until,
        "revoked_at": v.revoked_at,
        "predecessor_version": v.predecessor_version,
        "fingerprint": v.fingerprint(),
    }


def _version_from_dict(item: dict) -> KeyVersion:
    return KeyVersion(
        key_id=item["key_id"], version=item["version"],
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


def export_sealed(versions: list[KeyVersion], passphrase: str) -> bytes:
    """导出封存：PBKDF2 派生密钥 + AES-GCM 加密，含指纹与版本链。"""
    salt = os.urandom(SALT_BYTES)
    nonce = os.urandom(NONCE_BYTES)
    key = _derive_key(passphrase, salt, KDF_ITERATIONS)
    payload = json.dumps(
        {"versions": [_version_to_dict(v) for v in versions]},
        sort_keys=True).encode("utf-8")
    ciphertext = AESGCM(key).encrypt(nonce, payload, None)
    envelope = {
        "format": ARCHIVE_FORMAT,
        "kdf": {"algorithm": KDF_ALGORITHM, "iterations": KDF_ITERATIONS,
                "salt": _b64e(salt)},
        "nonce": _b64e(nonce),
        "ciphertext": _b64e(ciphertext),
    }
    return json.dumps(envelope, sort_keys=True).encode("utf-8")


def _validate_chain(versions: list[KeyVersion], fingerprints: list[str]) -> None:
    """校验指纹可复现、版本链完整（连续、前驱存在）。"""
    by_key: dict[str, list[KeyVersion]] = {}
    for v, fp in zip(versions, fingerprints):
        if v.fingerprint() != fp:
            raise CorruptArchiveError(
                f"fingerprint mismatch for {v.key_id} v{v.version}")
        by_key.setdefault(v.key_id, []).append(v)
    for key_id, items in by_key.items():
        nums = sorted(v.version for v in items)
        if nums != list(range(1, len(nums) + 1)):
            raise CorruptArchiveError(
                f"version chain of {key_id!r} is not contiguous: {nums}")
        by_version = {v.version: v for v in items}
        for v in items:
            if v.version == 1:
                if v.predecessor_version is not None:
                    raise CorruptArchiveError(
                        f"{key_id} v1 must not have a predecessor")
            elif v.predecessor_version != v.version - 1 \
                    or v.predecessor_version not in by_version:
                raise CorruptArchiveError(
                    f"{key_id} v{v.version} has broken predecessor link")


def import_sealed(blob: bytes, passphrase: str) -> list[KeyVersion]:
    """恢复：解密并校验指纹与版本链完整性。"""
    try:
        envelope = json.loads(blob.decode("utf-8"))
        if envelope.get("format") != ARCHIVE_FORMAT:
            raise CorruptArchiveError("unknown archive format")
        kdf_info = envelope["kdf"]
        if kdf_info["algorithm"] != KDF_ALGORITHM:
            raise CorruptArchiveError("unsupported kdf")
        salt = _b64d(kdf_info["salt"])
        iterations = int(kdf_info["iterations"])
        nonce = _b64d(envelope["nonce"])
        ciphertext = _b64d(envelope["ciphertext"])
    except CorruptArchiveError:
        raise
    except Exception as exc:  # JSON/键缺失/base64 等结构错误
        raise CorruptArchiveError(f"malformed archive: {exc}") from exc

    key = _derive_key(passphrase, salt, iterations)
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
    except InvalidTag as exc:
        # 口令错误或密文篡改：统一认证失败，不泄漏任何部分明文
        raise WrongPassphraseError("decryption failed: wrong passphrase "
                                   "or tampered ciphertext") from exc

    try:
        payload = json.loads(plaintext.decode("utf-8"))
        items = payload["versions"]
        versions = [_version_from_dict(it) for it in items]
        fingerprints = [it["fingerprint"] for it in items]
    except Exception as exc:
        raise CorruptArchiveError(f"corrupt payload: {exc}") from exc
    _validate_chain(versions, fingerprints)
    return versions
