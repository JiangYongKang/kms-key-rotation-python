"""封存与恢复测试：错误口令、篡改密文、版本链完整性。"""
from __future__ import annotations

import base64
import json
import logging

import pytest

from app.vault import (CorruptArchiveError, WrongPassphraseError,
                       export_sealed, import_sealed)

log = logging.getLogger("test.vault")


@pytest.fixture()
def versions(service):
    service.create_key("k")
    service.activate("k", 1)
    service.rotate("k", transition_seconds=30.0)
    return service.store.list_versions("k")


def test_roundtrip_reproduces_fingerprints_and_chain(versions):
    blob = export_sealed(versions, "correct-horse")
    back = import_sealed(blob, "correct-horse")
    log.info("input: export %d versions, restore -> fps=%s preds=%s",
             len(versions), [v.fingerprint()[:20] for v in back],
             [v.predecessor_version for v in back])
    assert [v.fingerprint() for v in back] == [v.fingerprint() for v in versions]
    assert [v.predecessor_version for v in back] == [None, 1]
    assert back[0].state == versions[0].state


def test_wrong_passphrase_fails(versions):
    blob = export_sealed(versions, "right")
    with pytest.raises(WrongPassphraseError) as exc:
        import_sealed(blob, "wrong")
    log.info("input: wrong passphrase -> %s", exc.value)


def test_tampered_ciphertext_fails_without_partial_plaintext(versions):
    blob = export_sealed(versions, "pw")
    env = json.loads(blob)
    ct = bytearray(base64.b64decode(env["ciphertext"]))
    ct[len(ct) // 2] ^= 0xFF  # 翻转密文中间字节
    env["ciphertext"] = base64.b64encode(bytes(ct)).decode()
    with pytest.raises(WrongPassphraseError):
        import_sealed(json.dumps(env).encode(), "pw")
    log.info("input: flipped ciphertext byte -> WrongPassphraseError, "
             "no partial plaintext returned")


def test_tampered_nonce_fails(versions):
    blob = export_sealed(versions, "pw")
    env = json.loads(blob)
    nonce = bytearray(base64.b64decode(env["nonce"]))
    nonce[0] ^= 1
    env["nonce"] = base64.b64encode(bytes(nonce)).decode()
    with pytest.raises(WrongPassphraseError):
        import_sealed(json.dumps(env).encode(), "pw")
    log.info("input: tampered nonce -> WrongPassphraseError")


def test_malformed_envelope_is_corrupt_archive(versions):
    with pytest.raises(CorruptArchiveError):
        import_sealed(b"not-json-at-all", "pw")
    with pytest.raises(CorruptArchiveError):
        import_sealed(b'{"format": "other"}', "pw")
    log.info("input: malformed envelopes -> CorruptArchiveError")


def test_broken_version_chain_rejected(versions):
    """解密后版本关系不完整（缺前驱版本）必须拒绝。"""
    blob = export_sealed(versions, "pw")
    env = json.loads(blob)
    # 用正确口令解出明文，删掉 v1 后重新加密（模拟不完整归档）
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from app.vault import _derive_key
    salt = base64.b64decode(env["kdf"]["salt"])
    key = _derive_key("pw", salt, env["kdf"]["iterations"])
    nonce = base64.b64decode(env["nonce"])
    payload = json.loads(AESGCM(key).decrypt(
        nonce, base64.b64decode(env["ciphertext"]), None))
    payload["versions"] = [v for v in payload["versions"] if v["version"] != 1]
    env["ciphertext"] = base64.b64encode(
        AESGCM(key).encrypt(nonce, json.dumps(payload).encode(), None)).decode()
    with pytest.raises(CorruptArchiveError) as exc:
        import_sealed(json.dumps(env).encode(), "pw")
    log.info("input: archive missing v1 -> CorruptArchiveError: %s", exc.value)


def test_restore_into_service_reproduces_state(tmp_path, clock, versions, service):
    from app.service import KeyService
    blob = service.export("pw")
    svc2 = KeyService(str(tmp_path / "other.json"), window_seconds=60.0,
                      clock=clock)
    svc2.restore(blob, "pw")
    restored = svc2.store.list_versions("k")
    log.info("restored into new service: states=%s",
             [(v.version, v.state.value) for v in restored])
    assert [v.fingerprint() for v in restored] == \
           [v.fingerprint() for v in versions]
    assert [v.state for v in restored] == [v.state for v in versions]
