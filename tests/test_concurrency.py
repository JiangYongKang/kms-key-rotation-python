"""并发测试：重复随机数竞争、轮转与验签并发的一致性。"""
from __future__ import annotations

import logging
import threading

from app.models import FailureReason

log = logging.getLogger("test.concurrency")


def _run_parallel(fn, count):
    barrier = threading.Barrier(count)
    results = [None] * count

    def worker(i):
        barrier.wait(timeout=10)
        results[i] = fn(i)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    return results


def test_concurrent_duplicate_nonce_exactly_one_wins(service):
    service.create_key("k")
    service.activate("k", 1)
    req = service.sign("k", "POST", b"pay", nonce="race-nonce")

    results = _run_parallel(lambda _: service.verify(req), 16)
    oks = [r for r in results if r.ok]
    replays = [r for r in results if r.reason == FailureReason.NONCE_REUSED]
    others = [r for r in results if not r.ok
              and r.reason != FailureReason.NONCE_REUSED]
    log.info("input: 16 threads verify same nonce -> ok=%d replay=%d other=%s",
             len(oks), len(replays),
             [r.reason for r in others])
    assert len(oks) == 1
    assert len(replays) == 15
    assert not others


def test_rotation_concurrent_with_verify_consistent(service, clock):
    """轮转与验签并发：每个请求的判定必须原子、结论唯一。"""
    service.create_key("k")
    service.activate("k", 1)
    reqs = [service.sign("k", "GET", b"data", nonce=f"cn-{i}") for i in range(16)]

    def action(i):
        if i == 0:
            service.rotate("k", transition_seconds=3600.0)
            return "rotated"
        return service.verify(reqs[i])

    results = _run_parallel(action, 16)
    verifies = [r for r in results if r != "rotated"]
    log.info("input: rotate + 15 verifies of v1 requests concurrently -> %s",
             [(r.ok, r.reason.value if r.reason else None) for r in verifies])
    # 过渡期内 v1 全部应通过；绝不允许出现签名/状态类的不一致拒绝
    assert all(r.ok for r in verifies), verifies
    # 轮转只发生一次，新版本为 v2
    assert service.store.active_version("k").version == 2


def test_concurrent_sign_uses_single_active_version(service):
    service.create_key("k")
    service.activate("k", 1)

    def action(i):
        if i == 0:
            service.rotate("k", transition_seconds=3600.0)
            return "rotated"
        return service.sign("k", "GET", b"x", nonce=f"s-{i}")

    results = _run_parallel(action, 16)
    signs = [r for r in results if r != "rotated"]
    versions = {r.version for r in signs}
    log.info("input: rotate + 15 concurrent signs -> versions used=%s", versions)
    # 每个签名都取自某一时刻的唯一 ACTIVE 版本，且都能通过验签
    assert versions <= {1, 2}
    for r in signs:
        assert service.verify(r).ok
