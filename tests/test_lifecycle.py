"""密钥多版本生命周期与过渡期边界测试。"""

from __future__ import annotations

from app.errors import KeyServiceError
from app.keys import KeyState
from app.signing import sign
from app.service import SignedRequest

import pytest


def signed_with(svc, version, ts, nonce, method="POST", path="/x", body=b"", headers=None):
    req = SignedRequest(version, ts, nonce, b"", method, path, body, dict(headers or {}))
    req.signature = sign(svc.get_key(version).private_bytes, svc._canonical(req))
    return req


def test_create_pending_then_activate(make_service, clock_state):
    holder, _ = clock_state
    svc = make_service()
    v = svc.create_key()
    assert svc.get_key(v).state is KeyState.PENDING

    # PENDING 不可验签 -> KEY_PENDING（可区分）
    dec = svc.verify_request(signed_with(svc, v, holder["t"], "n-pending"))
    assert (dec.accepted, dec.error_code) == (False, "KEY_PENDING")

    svc.activate(v)
    assert svc.get_key(v).state is KeyState.ACTIVE
    req = svc.sign_request("POST", "/x", b"")
    assert svc.verify_request(req).accepted


def test_no_active_key_sign_refused(make_service):
    svc = make_service()
    svc.create_key()  # 只有 PENDING
    with pytest.raises(KeyServiceError) as ei:
        svc.sign_request("POST", "/x", b"")
    assert ei.value.code.value == "NO_ACTIVE_KEY"


def test_rotate_moves_old_to_verify_only_and_new_active(make_service, clock_state):
    holder, _ = clock_state
    svc = make_service()
    v1 = svc.create_key()
    svc.activate(v1)
    v2 = svc.rotate(transition_seconds=100)
    assert v2 == v1 + 1
    assert svc.get_key(v1).state is KeyState.VERIFY_ONLY
    assert svc.get_key(v1).verify_until == holder["t"] + 100
    new_req = svc.sign_request("GET", "/a", b"")
    assert new_req.version == v2  # 轮转后新请求用当前版本签名


def test_transition_window_boundary_inclusive(make_service, clock_state):
    """过渡期边界：now == verify_until 仍可验签；now == verify_until+1 拒绝。"""
    holder, set_t = clock_state
    svc = make_service(skew=1000)  # 放大时间窗，排除时间窗干扰
    v1 = svc.create_key()
    svc.activate(v1)
    svc.rotate(transition_seconds=100)  # v1 VERIFY_ONLY，截止 t0+100
    t0 = holder["t"]

    # 边界点（含）：接受
    set_t(t0 + 100)
    dec = svc.verify_request(signed_with(svc, v1, t0 + 100, "edge-equal"))
    assert dec.accepted, dec

    # 刚过边界：KEY_VERIFY_WINDOW_EXPIRED
    set_t(t0 + 101)
    dec = svc.verify_request(signed_with(svc, v1, t0 + 101, "edge-after"))
    assert (dec.accepted, dec.error_code) == (False, "KEY_VERIFY_WINDOW_EXPIRED")


def test_old_version_verifies_within_transition_with_new_nonce(make_service):
    svc = make_service(skew=1000)
    v1 = svc.create_key()
    svc.activate(v1)
    svc.rotate(transition_seconds=1000)
    # 历史版本在过渡期内仍可验签
    dec = svc.verify_request(signed_with(svc, v1, 1_000_000, "legacy-1"))
    assert dec.accepted, dec
    # 历史版本同一 nonce 不可重放
    dec = svc.verify_request(signed_with(svc, v1, 1_000_000, "legacy-1"))
    assert dec.error_code == "NONCE_REPLAY"


def test_revoked_version_rejected_with_distinct_reason(make_service, clock_state):
    holder, _ = clock_state
    svc = make_service(skew=1000)
    v1 = svc.create_key()
    svc.activate(v1)
    svc.revoke(v1)

    dec = svc.verify_request(signed_with(svc, v1, holder["t"], "n-rev"))
    assert (dec.accepted, dec.error_code) == (False, "KEY_REVOKED")
    # 对已吊销版本签名也是非法操作（签名路径无当前 ACTIVE）
    with pytest.raises(KeyServiceError) as ei:
        svc.sign_request("GET", "/", b"")
    assert ei.value.code.value == "NO_ACTIVE_KEY"


def test_illegal_transitions_are_rejected(make_service):
    svc = make_service()
    v1 = svc.create_key()  # PENDING
    # PENDING -> VERIFY_ONLY 非法
    with pytest.raises(KeyServiceError) as ei:
        svc.transition(v1, KeyState.VERIFY_ONLY)
    assert ei.value.code.value == "ILLEGAL_TRANSITION"

    svc.activate(v1)
    svc.rotate(transition_seconds=100)
    # ACTIVE(v2) -> ACTIVE(v1) 非法：不能并存
    with pytest.raises(KeyServiceError) as ei:
        svc.transition(v1, KeyState.ACTIVE)
    assert ei.value.code.value == "ILLEGAL_TRANSITION"

    svc.revoke(v1)
    # REVOKED 为终态：重复吊销 / 复活均非法
    with pytest.raises(KeyServiceError) as ei:
        svc.revoke(v1)
    assert ei.value.code.value == "ILLEGAL_TRANSITION"
    with pytest.raises(KeyServiceError) as ei:
        svc.transition(v1, KeyState.ACTIVE)
    assert ei.value.code.value == "ILLEGAL_TRANSITION"


def test_unknown_version_distinct_reason(make_service):
    svc = make_service()
    dec = svc.verify_request(SignedRequest(404, 1, "x", b"", "GET", "/", b""))
    assert dec.error_code == "KEY_VERSION_NOT_FOUND"
