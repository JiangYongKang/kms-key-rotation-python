"""流水保留期与容量上限的边界行为。"""
from __future__ import annotations

import logging

import pytest

from app.models import FailureReason, JournalOutcome
from app.service import KeyService

log = logging.getLogger("test.retention")


@pytest.fixture()
def service(tmp_path, clock) -> KeyService:
    return KeyService(str(tmp_path / "state.json"), window_seconds=60.0,
                      retention_seconds=60.0, nonce_capacity=3, clock=clock)


@pytest.fixture()
def big_service(tmp_path, clock) -> KeyService:
    return KeyService(str(tmp_path / "state.json"), window_seconds=60.0,
                      retention_seconds=60.0, nonce_capacity=10_000, clock=clock)


def _ready(service):
    service.create_key("k")
    service.activate("k", 1)


def test_records_within_retention_are_never_dropped(big_service, clock):
    """时间窗/保留期内的记录绝不因清理被提前丢掉，重放仍被拒。"""
    _ready(big_service)
    req = big_service.sign("k", "POST", b"x", nonce="keep-me")
    assert big_service.verify(req).ok
    # 多次新请求会触发 evict，但保留期内的旧 nonce 必须仍在
    for i in range(20):
        r = big_service.sign("k", "GET", b"y", nonce=f"other-{i}")
        assert big_service.verify(r).ok
    replay = big_service.verify(req)
    log.info("input: replay within retention after %d other nonces -> %s",
             20, replay.reason)
    assert replay.reason == FailureReason.NONCE_REUSED


def test_capacity_full_refuses_new_nonce_with_distinct_reason(service, clock):
    """容量顶满又腾不出过期记录时：明确拒绝，原因可与其它失败区分。"""
    _ready(service)
    for i in range(3):
        r = service.sign("k", "GET", b"x", nonce=f"cap-{i}")
        assert service.verify(r).ok
    full_req = service.sign("k", "GET", b"x", nonce="cap-new")
    res = service.verify(full_req)
    log.info("input: capacity=3 full, new nonce -> reason=%s detail=%s",
             res.reason, res.detail)
    assert res.reason == FailureReason.NONCE_LOG_FULL

    # 容量满时重复 nonce 仍判重复（结论不被容量影响）
    first_req = service.sign("k", "GET", b"x", nonce="cap-0")
    replay = service.verify(first_req)
    assert replay.reason == FailureReason.NONCE_REUSED

    # 伪造签名的请求在进入流水前就被拒，不会因容量被放行
    forged = type(full_req)(**{**full_req.__dict__, "signature": b"\x00" * 64})
    assert service.verify(forged).reason == FailureReason.SIGNATURE_MISMATCH


def test_expired_records_free_capacity_and_accept_resumes(service, clock):
    """超过保留期后旧记录被腾退，新请求恢复接受；流水不无界增长。"""
    _ready(service)
    reqs = []
    for i in range(3):
        r = service.sign("k", "GET", b"x", nonce=f"old-{i}")
        assert service.verify(r).ok
        reqs.append(r)

    res_full = service.verify(service.sign("k", "GET", b"x", nonce="blocked"))
    assert res_full.reason == FailureReason.NONCE_LOG_FULL

    clock.advance(61.0)  # 超过保留期（60s）
    service.refresh()   # 显式清理，不影响签名/验签的正常路径
    log.info("input: after +61s refresh, journal len=%d",
             len(service.store.journal))
    assert len(service.store.journal) == 0

    fresh = service.sign("k", "GET", b"z", nonce="fresh")
    assert service.verify(fresh).ok
    # 保留期外旧 nonce 已腾退：在当前时间用它重新签名，应作为新请求接受
    reused = service.sign("k", "GET", b"z", nonce="old-0")
    assert service.verify(reused).ok


def test_cleanup_during_verify_does_not_block_window_decisions(service, clock):
    """验签路径上的清理只切过期前缀：窗口内请求照常判定为重放。"""
    _ready(service)
    keep = service.sign("k", "GET", b"x", nonce="kept")
    assert service.verify(keep).ok
    clock.advance(30.0)  # 在 60s 窗口内
    another = service.sign("k", "GET", b"x", nonce="another")
    assert service.verify(another).ok
    replay = service.verify(keep)
    log.info("input: +30s inside window replay -> %s", replay.reason)
    assert replay.reason == FailureReason.NONCE_REUSED


def test_retention_shorter_than_window_is_rejected(tmp_path, clock):
    """保留期短于验签时间窗会造成重放漏洞，构造时直接拒绝。"""
    with pytest.raises(ValueError):
        KeyService(str(tmp_path / "s.json"), window_seconds=300.0,
                   retention_seconds=60.0, nonce_capacity=10, clock=clock)


def test_evicted_nonce_outcomes_are_consistent(service, clock):
    """记录中保留的全部是保留期内的判定，结论只有 accepted/replayed。"""
    _ready(service)
    r = service.sign("k", "GET", b"x", nonce="once")
    assert service.verify(r).ok
    assert service.verify(r).reason == FailureReason.NONCE_REUSED
    recs = service.query_records()
    assert {x.outcome for x in recs} <= {JournalOutcome.ACCEPTED,
                                        JournalOutcome.REPLAYED}
    log.info("input: one accept + one replay -> %s",
             [(x.nonce, x.outcome.value) for x in recs])
