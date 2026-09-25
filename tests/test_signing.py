"""请求签名、重放防护与时间偏移测试。"""
from __future__ import annotations

import logging

from app.models import FailureReason

log = logging.getLogger("test.signing")


def _make_signed(service):
    service.create_key("k")
    service.activate("k", 1)
    return service.sign("k", "POST", b'{"op":"transfer"}', nonce="nonce-1")


def test_valid_request_accepted(service):
    req = _make_signed(service)
    res = service.verify(req)
    log.info("input: valid signed request -> ok=%s detail=%s", res.ok, res.detail)
    assert res.ok


def test_replay_rejected(service):
    req = _make_signed(service)
    first = service.verify(req)
    second = service.verify(req)
    log.info("input: same nonce twice -> first ok=%s, second reason=%s",
             first.ok, second.reason)
    assert first.ok
    assert second.reason == FailureReason.NONCE_REUSED


def test_timestamp_out_of_window(service, clock):
    req = _make_signed(service)
    clock.advance(61.0)  # 窗口 60s
    res = service.verify(req)
    log.info("input: drift=+61s window=60s -> reason=%s detail=%s",
             res.reason, res.detail)
    assert res.reason == FailureReason.TIMESTAMP_OUT_OF_WINDOW
    # 未来时间偏移同样拒绝
    req2 = service.sign("k", "POST", b"x", nonce="n-future")
    req2.timestamp += 120.0
    res2 = service.verify(req2)
    log.info("input: drift=-120s (future) -> reason=%s", res2.reason)
    assert res2.reason == FailureReason.TIMESTAMP_OUT_OF_WINDOW


def test_signature_mismatch_on_tampered_payload(service):
    req = _make_signed(service)
    req.payload = b'{"op":"steal"}'
    res = service.verify(req)
    log.info("input: tampered payload -> reason=%s detail=%s", res.reason, res.detail)
    assert res.reason == FailureReason.SIGNATURE_MISMATCH


def test_signature_covers_method(service):
    req = _make_signed(service)
    req.method = "GET"  # 方法被改，签名应不匹配
    res = service.verify(req)
    log.info("input: method changed POST->GET -> reason=%s", res.reason)
    assert res.reason == FailureReason.SIGNATURE_MISMATCH


def test_forged_signature_does_not_poison_nonce(service):
    """伪造签名的请求不得占用 nonce（否则可 DoS 合法请求）。"""
    req = _make_signed(service)
    forged = type(req)(**{**req.__dict__, "signature": b"\x00" * 64})
    bad = service.verify(forged)
    good = service.verify(req)
    log.info("input: forged then genuine same nonce -> forged=%s genuine ok=%s",
             bad.reason, good.ok)
    assert bad.reason == FailureReason.SIGNATURE_MISMATCH
    assert good.ok


def test_nonce_store_evicts_old_entries(service, clock):
    service.create_key("k")
    service.activate("k", 1)
    for i in range(5):
        r = service.sign("k", "GET", b"x", nonce=f"n{i}")
        assert service.verify(r).ok
    assert len(service.signer.nonces) == 5
    clock.advance(3600.0)  # 远超窗口，旧记录应被淘汰
    r = service.sign("k", "GET", b"x", nonce="fresh")
    assert service.verify(r).ok
    size = len(service.signer.nonces)
    log.info("input: advance 3600s then 1 new nonce -> store size=%d", size)
    assert size == 1  # 无界增长被抑制


def test_unknown_key_and_version(service):
    service.create_key("k")
    service.activate("k", 1)
    req = service.sign("k", "GET", b"x", nonce="n1")
    req.key_id = "ghost"
    res = service.verify(req)
    log.info("input: unknown key_id -> reason=%s", res.reason)
    assert res.reason == FailureReason.KEY_NOT_FOUND
    req.key_id = "k"
    req.version = 99
    res = service.verify(req)
    log.info("input: unknown version -> reason=%s", res.reason)
    assert res.reason == FailureReason.KEY_NOT_FOUND
