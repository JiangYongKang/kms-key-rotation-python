"""密钥生命周期与过渡期边界测试。"""
from __future__ import annotations

import logging

import pytest

from app.keystore import IllegalTransitionError
from app.models import FailureReason, KeyState
from app.service import KeyService

log = logging.getLogger("test.lifecycle")


def test_pending_key_cannot_sign(service):
    service.create_key("k")
    out = service.sign("k", "POST", b"payload", nonce="n1")
    log.info("input: sign with PENDING key -> reason=%s detail=%s",
             out.reason, out.detail)
    assert out.reason == FailureReason.KEY_PENDING


def test_illegal_transitions_rejected(service, clock):
    service.create_key("k")
    service.activate("k", 1)
    # ACTIVE -> PENDING 非法
    with pytest.raises(IllegalTransitionError) as exc:
        service.store.transition("k", 1, KeyState.PENDING, clock())
    log.info("input: ACTIVE->PENDING -> rejected: %s", exc.value)
    assert exc.value.src == KeyState.ACTIVE
    # 吊销后任何迁移非法
    service.revoke("k", 1)
    with pytest.raises(IllegalTransitionError):
        service.store.transition("k", 1, KeyState.ACTIVE, clock())
    log.info("input: REVOKED->ACTIVE -> rejected (illegal_transition)")


def test_rotation_and_transition_boundary(service, clock):
    service.create_key("k")
    service.activate("k", 1)
    # 轮转前用 v1 签一个请求
    old_req = service.sign("k", "GET", b"old", nonce="n-old")
    assert old_req.version == 1

    new_kv = service.rotate("k", transition_seconds=30.0)
    log.info("rotate: new version=%s state=%s, v1 verify_only_until=%s",
             new_kv.version, new_kv.state,
             service.store.get("k", 1).verify_only_until)
    assert new_kv.version == 2 and new_kv.state == KeyState.ACTIVE
    assert service.store.get("k", 1).state == KeyState.VERIFY_ONLY

    # 新请求使用当前版本签名
    new_req = service.sign("k", "GET", b"new", nonce="n-new")
    assert new_req.version == 2

    # 过渡期内（边界前一秒）历史版本仍可验签
    clock.advance(29.0)
    res = service.verify(old_req)
    log.info("input: v1 request at T+29 (until T+30) -> ok=%s detail=%s",
             res.ok, res.detail)
    assert res.ok, res

    # 过渡期结束（到达边界）必须拒绝，原因可区分
    clock.advance(1.0)
    res = service.verify(old_req)
    log.info("input: v1 request at T+30 (boundary) -> reason=%s detail=%s",
             res.reason, res.detail)
    assert res.reason == FailureReason.TRANSITION_EXPIRED

    # refresh 后 v1 自动吊销，此后原因变为 key_revoked
    service.refresh()
    assert service.store.get("k", 1).state == KeyState.REVOKED
    res = service.verify(old_req)
    log.info("input: v1 request after refresh -> reason=%s", res.reason)
    assert res.reason == FailureReason.KEY_REVOKED


def test_revoked_key_cannot_sign_or_verify(service, clock):
    service.create_key("k")
    service.activate("k", 1)
    req = service.sign("k", "POST", b"x", nonce="n1")
    service.revoke("k", 1)
    out = service.sign("k", "POST", b"x", nonce="n2")
    log.info("input: sign with revoked key -> reason=%s", out.reason)
    assert out.reason == FailureReason.KEY_REVOKED
    res = service.verify(req)
    log.info("input: verify with revoked key -> reason=%s", res.reason)
    assert res.reason == FailureReason.KEY_REVOKED


def test_state_persisted_and_reloaded(tmp_path, clock):
    path = str(tmp_path / "state.json")
    svc = KeyService(path, window_seconds=60.0, clock=clock)
    svc.create_key("k")
    svc.activate("k", 1)
    svc.rotate("k", transition_seconds=30.0)
    fp_before = svc.store.get("k", 2).fingerprint()

    svc2 = KeyService(path, window_seconds=60.0, clock=clock)
    svc2.store.load()
    v1 = svc2.store.get("k", 1)
    v2 = svc2.store.get("k", 2)
    log.info("reloaded: v1=%s v2=%s fp_match=%s", v1.state, v2.state,
             v2.fingerprint() == fp_before)
    assert v1.state == KeyState.VERIFY_ONLY
    assert v2.state == KeyState.ACTIVE
    assert v2.fingerprint() == fp_before
    assert v2.predecessor_version == 1
