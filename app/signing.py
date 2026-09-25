"""请求规范化、Ed25519 签名与验签。

签名覆盖请求方法 method、路径 path、关键负载（headers 的稳定序列化
以及 body 的 SHA-256），并绑定 version/timestamp/nonce，使换方法、
改负载、重放旧请求都会导致 SIGNATURE_MISMATCH 或被流水判定拦截。

规范化串（逐行 LF，UTF-8）：
    LOCAL-KMS-SIGN-V1
    method: <METHOD 大写>
    path: <path>
    version: <v>
    timestamp: <t>
    nonce: <n>
    header.<name 小写且按名排序>: <值>
    ...
    sha256-body: <body 的 SHA-256 十六进制>
"""

from __future__ import annotations

import hashlib
from typing import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

SIGNING_SCHEME = "LOCAL-KMS-SIGN-V1"


def canonical_request(
    method: str,
    path: str,
    body: bytes,
    headers: Mapping[str, str],
    version: int,
    timestamp: int,
    nonce: str,
) -> bytes:
    lines = [
        SIGNING_SCHEME,
        f"method: {method.upper()}",
        f"path: {path}",
        f"version: {version}",
        f"timestamp: {timestamp}",
        f"nonce: {nonce}",
    ]
    for name in sorted(headers, key=lambda k: k.lower()):
        lines.append(f"header.{name.lower()}: {headers[name]}")
    lines.append(f"sha256-body: {hashlib.sha256(body).hexdigest()}")
    return "\n".join(lines).encode("utf-8")


def sign(private_bytes: bytes, message: bytes) -> bytes:
    key = Ed25519PrivateKey.from_private_bytes(private_bytes)
    return key.sign(message)


def verify(public_bytes: bytes, message: bytes, signature: bytes) -> bool:
    """任何格式/长度/签名异常都归一为 False，不向上抛异常。"""
    try:
        Ed25519PublicKey.from_public_bytes(public_bytes).verify(signature, message)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
