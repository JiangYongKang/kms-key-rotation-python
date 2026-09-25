"""密钥材料封存与恢复（口令派生密钥加密，可离线复现）。

封套 envelope（JSON）字段：
{
  "scheme": "local-kms-seal/v1",
  "kdf": {"name": "scrypt", "n": 16384, "r": 8, "p": 1, "length": 32},
  "versions": [1, 2, ...],          # 被封装的版本号集合（参与 AAD 绑定）
  "pw_verifier": {                  # 口令校验器：区分 BAD_PASSWORD / SEAL_TAMPERED
      "salt": <b64>, "nonce": <b64>, "ciphertext": <b64>
  },
  "payload": {
      "salt": <b64>, "nonce": <b64>, "ciphertext": <b64>,
      "aad": "<utf8 规范化 JSON 字符串>"
  }
}

payload 明文（AES-GCM 内部，受认证保护）：
  {"materials": {"<version>": <私钥种子 b64>}, "metadata": { ... 版本关系/指纹 ... }}

失败归类与顺序：
  1. 封套结构损坏/字段缺失 -> SEAL_TAMPERED（无法进入口令判定）；
  2. 口令校验器 GCM 失败   -> BAD_PASSWORD（口令错误无法与校验器被篡改
     区分，按口令错误归类；口令正确时校验器必然通过）；
  3. 载荷 GCM 失败/AAD 不符 -> SEAL_TAMPERED（口令已确认正确）；
  4. 载荷内部版本关系/指纹不一致 -> INCOMPLETE_VERSION_SET / FINGERPRINT_MISMATCH。
AES-GCM 是认证加密：认证失败时不返回任何明文，满足“不得泄漏部分明文”。
"""

from __future__ import annotations

import base64
import dataclasses
import json
import os
from typing import Any, Mapping

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from app.errors import ErrorCode, KeyServiceError

SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
KEY_LEN = 32  # AES-256
NONCE_LEN = 12
SALT_LEN = 16
SCHEME = "local-kms-seal/v1"
PW_VERIFIER_PLAINTEXT = b"local-kms-seal/v1 password check"
PW_VERIFIER_AAD = b"local-kms-seal/v1/pw-verifier"


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text, validate=True)


def _derive(password: str, salt: bytes, length: int = KEY_LEN) -> bytes:
    return Scrypt(salt=salt, length=length, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P).derive(
        password.encode("utf-8")
    )


def _aad(envelope: Mapping[str, Any]) -> bytes:
    """把方案、KDF 参数与版本号集合规范化后作为 AAD（结构性绑定）。"""
    bound = {
        "scheme": envelope["scheme"],
        "kdf": envelope["kdf"],
        "versions": list(envelope["versions"]),
    }
    return json.dumps(bound, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclasses.dataclass
class Seal:
    envelope: dict[str, Any]

    def to_json(self) -> str:
        return json.dumps(self.envelope, sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_json(cls, text: str) -> "Seal":
        try:
            envelope = json.loads(text)
        except (ValueError, TypeError) as exc:
            raise KeyServiceError(ErrorCode.SEAL_TAMPERED, "封套不是合法 JSON") from exc
        required = {"scheme", "kdf", "versions", "pw_verifier", "payload"}
        if not isinstance(envelope, dict) or not required <= envelope.keys():
            raise KeyServiceError(ErrorCode.SEAL_TAMPERED, "封套字段不完整")
        return cls(envelope)


def seal_materials(
    materials: Mapping[int, bytes],
    password: str,
    metadata: dict[str, Any] | None = None,
) -> Seal:
    """把 version -> 私钥种子与版本关系元数据封装成口令保护的封套。

    元数据与私钥一同位于 GCM 载荷内，任何篡改都会导致 SEAL_TAMPERED；
    语义层面的不一致由恢复方进一步归类。
    """
    versions = sorted(materials)
    envelope: dict[str, Any] = {
        "scheme": SCHEME,
        "kdf": {"name": "scrypt", "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P, "length": KEY_LEN},
        "versions": versions,
    }

    # 口令校验器（独立 salt/nonce/key）
    salt_v = os.urandom(SALT_LEN)
    ve = _derive(password, salt_v)
    nonce_v = os.urandom(NONCE_LEN)
    ct_v = AESGCM(ve).encrypt(nonce_v, PW_VERIFIER_PLAINTEXT, PW_VERIFIER_AAD)
    envelope["pw_verifier"] = {"salt": _b64e(salt_v), "nonce": _b64e(nonce_v), "ciphertext": _b64e(ct_v)}

    # 私钥材料 + 版本关系元数据（另一把派生密钥；AAD 绑定版本集合与方案参数）
    salt_k = os.urandom(SALT_LEN)
    ke = _derive(password, salt_k)
    plaintext = json.dumps(
        {
            "materials": {str(v): _b64e(materials[v]) for v in versions},
            "metadata": metadata or {},
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    aad = _aad(envelope)
    nonce_k = os.urandom(NONCE_LEN)
    ct_k = AESGCM(ke).encrypt(nonce_k, plaintext, aad)
    envelope["payload"] = {
        "salt": _b64e(salt_k),
        "nonce": _b64e(nonce_k),
        "ciphertext": _b64e(ct_k),
        "aad": aad.decode("utf-8"),
    }
    return Seal(envelope)


def unseal_materials(
    seal: Seal, password: str
) -> tuple[dict[str, Any], dict[int, bytes]]:
    """返回 (metadata, version -> 私钥种子)。

    失败抛 BAD_PASSWORD 或 SEAL_TAMPERED；认证失败时没有任何明文产出。
    """
    env = seal.envelope
    try:
        ver = env["pw_verifier"]
        ve = _derive(password, _b64d(ver["salt"]))
        AESGCM(ve).decrypt(
            _b64d(ver["nonce"]), _b64d(ver["ciphertext"]), PW_VERIFIER_AAD
        )
    except KeyServiceError:
        raise
    except (InvalidTag, ValueError, TypeError, KeyError) as exc:
        # 口令错误与校验器本身损坏无法区分，统一归为口令错误
        raise KeyServiceError(ErrorCode.BAD_PASSWORD, "口令错误，无法通过封套口令校验") from exc

    try:
        pl = env["payload"]
        ke = _derive(password, _b64d(pl["salt"]))
        aad = _aad(env)
        if pl.get("aad") != aad.decode("utf-8"):
            raise KeyServiceError(ErrorCode.SEAL_TAMPERED, "封套版本关系(AAD)与载荷不一致")
        plaintext = AESGCM(ke).decrypt(_b64d(pl["nonce"]), _b64d(pl["ciphertext"]), aad)
        data = json.loads(plaintext)
        versions = env["versions"]
        raw = data["materials"]
        if set(map(str, versions)) != set(raw):
            raise KeyServiceError(ErrorCode.SEAL_TAMPERED, "封套版本集合与私钥材料不一致")
        materials = {int(v): _b64d(raw[str(v)]) for v in versions}
        metadata = data.get("metadata", {})
        if not isinstance(metadata, dict):
            raise KeyServiceError(ErrorCode.SEAL_TAMPERED, "封套元数据结构损坏")
    except KeyServiceError:
        raise
    except (InvalidTag, ValueError, TypeError, KeyError) as exc:
        raise KeyServiceError(ErrorCode.SEAL_TAMPERED, "封套密文被篡改或结构损坏") from exc

    return metadata, materials
