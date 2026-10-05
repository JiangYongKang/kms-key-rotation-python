"""重启与多进程场景：同一 nonce 全局限一次、状态原子、旧格式向后兼容。"""
from __future__ import annotations

import json
import logging
import multiprocessing as mp
import os

from app.models import FailureReason
from app.service import KeyService

log = logging.getLogger("test.persistence")


def _seed(path: str) -> None:
    svc = KeyService(path, window_seconds=60.0,
                     retention_seconds=60.0, nonce_capacity=1000)
    svc.create_key("k")
    svc.activate("k", 1)


def _concurrent_verify_worker(path: str, nonce: str, queue) -> None:
    try:
        svc = KeyService(path, window_seconds=60.0,
                         retention_seconds=60.0, nonce_capacity=1000)
        req = svc.sign("k", "POST", b"pay", nonce=nonce)
        res = svc.verify(req)
        queue.put({"ok": res.ok,
                   "reason": res.reason.value if res.reason else None})
    except Exception as exc:  # pragma: no cover - 子进程失败也要带回主进程
        queue.put({"ok": False, "reason": f"worker-error: {exc!r}"})


def test_replay_verdict_survives_restart(tmp_path, clock):
    """重启后（新进程视角的新加载）已通过的请求仍判重复，绝不放行。"""
    path = str(tmp_path / "state.json")
    svc = KeyService(path, window_seconds=60.0,
                     retention_seconds=60.0, nonce_capacity=1000, clock=clock)
    svc.create_key("k")
    svc.activate("k", 1)
    req = svc.sign("k", "POST", b"pay", nonce="persist-nonce")
    first = svc.verify(req)
    assert first.ok

    reloaded = KeyService(path, window_seconds=60.0,
                          retention_seconds=60.0, nonce_capacity=1000,
                          clock=clock)
    second = reloaded.verify(req)
    log.info("input: same nonce after reload -> ok=%s reason=%s basis=%s",
             second.ok, second.reason, second.detail)
    assert second.reason == FailureReason.NONCE_REUSED

    # 再次“重启”结论不变：加载幂等
    reloaded2 = KeyService(path, window_seconds=60.0,
                           retention_seconds=60.0, nonce_capacity=1000,
                           clock=clock)
    third = reloaded2.verify(req)
    assert third.reason == FailureReason.NONCE_REUSED


def test_same_nonce_accepted_by_exactly_one_process(tmp_path):
    """多个工作进程共用同一状态文件：同一 nonce 只有一个进程放行。"""
    path = str(tmp_path / "state.json")
    _seed(path)

    ctx = mp.get_context("spawn")
    queue = ctx.Queue()
    procs = [ctx.Process(target=_concurrent_verify_worker,
                         args=(path, "shared-nonce", queue))
             for _ in range(8)]
    for p in procs:
        p.start()
    outcomes = [queue.get(timeout=30) for _ in procs]
    for p in procs:
        p.join(timeout=10)

    oks = [o for o in outcomes if o["ok"]]
    replays = [o for o in outcomes if o["reason"] == "nonce_reused"]
    log.info("input: 8 processes verify nonce 'shared-nonce' -> ok=%d "
             "replay=%d outcomes=%s", len(oks), len(replays), outcomes)
    assert len(oks) == 1, outcomes
    assert len(replays) == 7, outcomes

    # 最终磁盘状态里该 nonce 恰好一条 accepted
    svc = KeyService(path, window_seconds=60.0, retention_seconds=60.0)
    recs = svc.query_records()
    accepted = [r for r in recs if r.nonce == "shared-nonce"
                and r.outcome.value == "accepted"]
    assert len(accepted) == 1
    # 状态文件保持合法 JSON（原子写未被并发破坏）
    with open(path, encoding="utf-8") as f:
        json.load(f)


def test_key_change_and_journal_commit_atomically(tmp_path, clock):
    """轮转与流水在同一文件原子生效：磁盘上密钥版本与流水始终对得上。"""
    path = str(tmp_path / "state.json")
    svc = KeyService(path, window_seconds=60.0,
                     retention_seconds=60.0, nonce_capacity=1000, clock=clock)
    svc.create_key("k")
    svc.activate("k", 1)
    req1 = svc.sign("k", "GET", b"x", nonce="a")
    assert svc.verify(req1).ok
    svc.rotate("k", transition_seconds=300.0)

    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    assert data["format"] == "kms-state-v2"
    assert [v["version"] for v in data["keys"]["k"]] == [1, 2]
    assert any(n["nonce"] == "a" and n["outcome"] == "accepted"
               for n in data["nonces"])
    assert data["nonce_seq"] >= 1

    reloaded = KeyService(path, window_seconds=60.0,
                          retention_seconds=60.0, nonce_capacity=1000,
                          clock=clock)
    assert reloaded.store.active_version("k").version == 2
    assert reloaded.verify(req1).reason == FailureReason.NONCE_REUSED


def test_legacy_state_file_loads_and_upgrades(tmp_path, clock):
    """旧版本（无 format 的纯密钥映射）状态文件可直接读取并自动升级。"""
    path = str(tmp_path / "state.json")
    # 先用当前实现造一份状态，再降级成旧格式（剥掉 format/nonces）
    svc = KeyService(path, window_seconds=60.0,
                     retention_seconds=60.0, nonce_capacity=1000, clock=clock)
    svc.create_key("k")
    svc.activate("k", 1)
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    legacy = data["keys"]
    with open(path, "w", encoding="utf-8") as f:
        json.dump(legacy, f)

    upgraded = KeyService(path, window_seconds=60.0,
                          retention_seconds=60.0, nonce_capacity=1000,
                          clock=clock)
    kv = upgraded.store.get("k", 1)
    assert kv is not None and kv.state.value == "active"
    # 首次写操作后格式升级，旧状态不丢失
    upgraded.refresh()
    upgraded.rotate("k", transition_seconds=300.0)
    with open(path, encoding="utf-8") as f:
        new_data = json.load(f)
    assert new_data["format"] == "kms-state-v2"
    assert [v["version"] for v in new_data["keys"]["k"]] == [1, 2]
    log.info("legacy file upgraded in place, no manual migration needed")


def test_sealed_archive_restores_into_journal_state(tmp_path, clock):
    """升级后之前导出的封存归档仍可恢复，并与已有请求流水共存。"""
    from app import vault

    archive_path = str(tmp_path / "archive.json")
    old = KeyService(archive_path, window_seconds=60.0,
                     retention_seconds=60.0, nonce_capacity=1000, clock=clock)
    old.create_key("archived")
    old.activate("archived", 1)
    old.rotate("archived", transition_seconds=300.0)
    blob = old.export("vault-pw")  # 模拟升级前已导出的归档

    target = str(tmp_path / "current.json")
    cur = KeyService(target, window_seconds=60.0,
                     retention_seconds=60.0, nonce_capacity=1000, clock=clock)
    cur.create_key("live")
    cur.activate("live", 1)
    req = cur.sign("live", "GET", b"x", nonce="live-n")
    assert cur.verify(req).ok

    cur.restore(blob, "vault-pw")  # 旧归档恢复进当前状态
    assert cur.store.active_version("archived").version == 2
    # 归档恢复不改变流水：已有重放判定保持不变
    assert cur.verify(req).reason == FailureReason.NONCE_REUSED
    # 恢复后状态仍是统一新格式、文件可被新进程加载
    again = KeyService(target, window_seconds=60.0,
                       retention_seconds=60.0, nonce_capacity=1000, clock=clock)
    assert again.store.active_version("archived").version == 2
    assert again.store.active_version("live").version == 1
    with open(target, encoding="utf-8") as f:
        assert json.load(f)["format"] == "kms-state-v2"
    log.info("input: old sealed archive restored alongside live journal")
