"""密钥材料封存与恢复测试。"""

from __future__ import annotations

import base64
import json

import pytest

from app.errors import ErrorCode, KeyServiceError
from app.sealing import SCRYPT_N, SCRYPT_P, SCRYPT_R, Seal, seal_materials
from app.signing import sign
from app.service import SignedRequest


def setup_rotated(svc):
    v1 = svc.create_key()
    svc.activate(v1)
    v2 = svc.rotate(transition_seconds=500)
    return v1, v2


def test_seal_roundtrip_versions_and_fingerprints_reproducible(make_service):
    svc = make_service()
    v1, v2 = setup_rotated(svc)
    before = svc.list_versions()
    seal = svc.export_sealed("correct horse battery staple")

    svc2 = make_service()
    svc2.restore_sealed(seal, "correct horse battery staple")
    after = svc2.list_versions()

    # 版本关系与指纹逐字段可复现
    assert before == after
    assert [k["version"] for k in after] == [v1, v2]
    assert svc2.get_key(v1).fingerprint() == svc.get_key(v1).fingerprint()
    assert svc2.get_key(v2).fingerprint() == svc.get_key(v2).fingerprint()

    # 恢复的私钥可继续完成验签（指纹/材料一致）
    req = SignedRequest(v1, 1_000_000, "after-restore", b"", "GET", "/", b"")
    req.signature = sign(svc2.get_key(v1).private_bytes, svc2._canonical(req))
    assert svc2.verify_request(req).accepted


def test_wrong_password_is_bad_password(make_service):
    svc = make_service()
    setup_rotated(svc)
    seal = svc.export_sealed("right-pw")
    svc2 = make_service()
    with pytest.raises(KeyServiceError) as ei:
        svc2.restore_sealed(seal, "wrong-pw")
    assert ei.value.code is ErrorCode.BAD_PASSWORD
    # 失败后不得写入任何密钥版本（无半成品泄漏）
    assert svc2.list_versions() == []


def test_tampered_ciphertext_is_seal_tampered(make_service):
    svc = make_service()
    setup_rotated(svc)
    seal = svc.export_sealed("pw")

    env = json.loads(seal.to_json())
    ct = bytearray(base64.b64decode(env["payload"]["ciphertext"]))
    ct[len(ct) // 2] ^= 0xFF
    env["payload"]["ciphertext"] = base64.b64encode(bytes(ct)).decode()

    svc2 = make_service()
    with pytest.raises(KeyServiceError) as ei:
        svc2.restore_sealed(Seal(env), "pw")
    assert ei.value.code is ErrorCode.SEAL_TAMPERED
    assert svc2.list_versions() == []  # 不泄漏部分明文/半成品


def test_tampered_aad_version_list_is_seal_tampered(make_service):
    svc = make_service()
    setup_rotated(svc)
    seal = svc.export_sealed("pw")

    # 篡改 AAD 绑定的外层版本关系：口令正确也必须失败
    env = json.loads(seal.to_json())
    env["versions"] = [1]
    svc2 = make_service()
    with pytest.raises(KeyServiceError) as ei:
        svc2.restore_sealed(Seal(env), "pw")
    assert ei.value.code is ErrorCode.SEAL_TAMPERED


def _export_parts(svc):
    """返回 (materials, 完整 metadata)，供构造异常封套。"""
    materials = {v: svc.state.private_bytes(v) for v in svc.state.keys}
    listing = svc.list_versions()
    keys_meta = []
    for item in listing:
        km = svc.get_key(int(item["version"]))
        keys_meta.append(
            {
                "version": item["version"],
                "state": item["state"],
                "created_at": item["created_at"],
                "verify_until": item["verify_until"],
                "public_b64": base64.b64encode(km.public_bytes).decode("ascii"),
                "fingerprint": item["fingerprint"],
            }
        )
    metadata = {"current_version": svc.state.current_version, "exported_at": 1, "keys": keys_meta}
    return materials, metadata


def test_incomplete_version_context_is_incomplete_set(make_service):
    svc = make_service()
    setup_rotated(svc)
    materials, metadata = _export_parts(svc)

    # 元数据漏掉版本 1（私钥里仍有两个版本）-> 版本关系不完整
    metadata["keys"] = [k for k in metadata["keys"] if k["version"] != 1]
    bad_seal = seal_materials(materials, "pw", metadata)

    svc2 = make_service()
    with pytest.raises(KeyServiceError) as ei:
        svc2.restore_sealed(bad_seal, "pw")
    assert ei.value.code is ErrorCode.INCOMPLETE_VERSION_SET
    assert svc2.list_versions() == []


def test_current_version_not_in_set_is_incomplete_set(make_service):
    svc = make_service()
    setup_rotated(svc)
    materials, metadata = _export_parts(svc)
    metadata["current_version"] = 999  # 指向集合外版本
    bad_seal = seal_materials(materials, "pw", metadata)
    svc2 = make_service()
    with pytest.raises(KeyServiceError) as ei:
        svc2.restore_sealed(bad_seal, "pw")
    assert ei.value.code is ErrorCode.INCOMPLETE_VERSION_SET


def test_fingerprint_mismatch_is_detected(make_service):
    svc = make_service()
    setup_rotated(svc)
    materials, metadata = _export_parts(svc)

    # 元数据指纹与私钥可导出的公钥不一致 -> FINGERPRINT_MISMATCH
    metadata["keys"][0]["fingerprint"] = "0" * 64
    bad_seal = seal_materials(materials, "pw", metadata)

    svc2 = make_service()
    with pytest.raises(KeyServiceError) as ei:
        svc2.restore_sealed(bad_seal, "pw")
    assert ei.value.code is ErrorCode.FINGERPRINT_MISMATCH
    assert svc2.list_versions() == []


def test_empty_materials_is_incomplete_set(make_service):
    svc = make_service()
    bad_seal = seal_materials({}, "pw", {"current_version": None, "keys": []})
    with pytest.raises(KeyServiceError) as ei:
        svc.restore_sealed(bad_seal, "pw")
    assert ei.value.code is ErrorCode.INCOMPLETE_VERSION_SET


def test_malformed_envelope_is_seal_tampered():
    with pytest.raises(KeyServiceError) as ei:
        Seal.from_json("{not-json")
    assert ei.value.code is ErrorCode.SEAL_TAMPERED


def test_kdf_parameters_documented_in_envelope(make_service):
    svc = make_service()
    setup_rotated(svc)
    seal = svc.export_sealed("pw")
    kdf = seal.envelope["kdf"]
    assert kdf == {"name": "scrypt", "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P, "length": 32}
    assert SCRYPT_N >= 2**14
