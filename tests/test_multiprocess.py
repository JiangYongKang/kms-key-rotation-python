"""多进程与重启：重复判定一致性、状态/流水原子生效、旧格式兼容。"""
from __future__ import annotations

import json
import logging
import multiprocessing
import os

from app.models import FailureReason, KeyState
from app.service import KeyService
from app.state import STATE_FORMAT_V2, key_version_to_dict

log = logging.getLogger("test.multiprocess")


def _verify_in_process(state_path, req, queue):
    """子进程入口：独立加载同一份状态文件后验签。"""
    svc = KeyService(state_path, window_seconds=300.0)  # 真实时钟
    res = svc.verify(req)
    queue.put((os.getpid(), res.ok, res.reason.value if res.reason else None))


def test_restart_keeps_replay_verdict(tmp_path, clock):
    """进程重启后，已通过的请求再提交仍判重复，结论与重启前一致。"""
    path = str(tmp_path / "state.json")
    svc1 = KeyService(path, window_seconds=60.0, clock=clock)
    svc1.create_key("k")
    svc1.activate("k", 1)
    req = svc1.sign("k", "POST", b"pay", nonce="restart-nonce")
    first = svc1.verify(req)

    # 模拟重启：全新实例重新加载同一份状态文件
    svc2 = KeyService(path, window_seconds=60.0, clock=clock)
    second = svc2.verify(req)
    log.info("input: verify nonce=%r before/after restart -> first ok=%s, "
             "after restart reason=%s", req.nonce, first.ok, second.reason)
    assert first.ok
    assert second.reason == FailureReason.NONCE_REUSED


def test_rotation_and_ledger_recover_together(tmp_path, clock):
    """密钥版本变化与请求流水一起落盘：重启后两边都对得上。"""
    path = str(tmp_path / "state.json")
    svc1 = KeyService(path, window_seconds=60.0, clock=clock)
    svc1.create_key("k")
    svc1.activate("k", 1)
    svc1.rotate("k", transition_seconds=3600.0)
    req = svc1.sign("k", "GET", b"data", nonce="atomic-nonce")
    assert svc1.verify(req).ok

    svc2 = KeyService(path, window_seconds=60.0, clock=clock)
    svc2._state.reload_readonly()
    active = svc2.store.active_version("k")
    records = svc2.query_ledger(key_id="k")
    log.info("after restart: active=v%s state=%s, ledger=%s",
             active.version, active.state,
             [(r.nonce, r.version, r.decision) for r in records])
    assert active.version == 2 and active.state == KeyState.ACTIVE
    assert [r.nonce for r in records] == ["atomic-nonce"]
    assert records[0].version == 2
    # 重启后同一请求仍判重
    assert svc2.verify(req).reason == FailureReason.NONCE_REUSED


def test_multiprocess_same_nonce_exactly_one_wins(tmp_path):
    """多进程共用同一状态文件：同一 nonce 最多一个进程放行。"""
    path = str(tmp_path / "state.json")
    svc = KeyService(path, window_seconds=300.0)  # 真实时钟，子进程可复现
    svc.create_key("k")
    svc.activate("k", 1)
    req = svc.sign("k", "POST", b"pay", nonce="mp-nonce")

    ctx = multiprocessing.get_context("fork")
    queue = ctx.Queue()
    workers = [ctx.Process(target=_verify_in_process, args=(path, req, queue))
               for _ in range(8)]
    for w in workers:
        w.start()
    for w in workers:
        w.join(timeout=60)
    results = [queue.get(timeout=10) for _ in workers]
    oks = [r for r in results if r[1]]
    replays = [r for r in results if r[2] == "nonce_reused"]
    others = [r for r in results if not r[1] and r[2] != "nonce_reused"]
    log.info("input: 8 processes verify same nonce -> ok=%s replay=%d other=%s",
             [r[0] for r in oks], len(replays), others)
    assert len(oks) == 1
    assert len(replays) == 7
    assert not others

    # 换一个新进程再提交，结论仍然是重复
    svc2 = KeyService(path, window_seconds=300.0)
    again = svc2.verify(req)
    log.info("input: yet another process verifies -> reason=%s", again.reason)
    assert again.reason == FailureReason.NONCE_REUSED


def test_v1_state_file_loads_and_upgrades(tmp_path, clock):
    """旧版（v1 裸密钥字典）状态文件无需人工迁移，加载后照常工作。"""
    path = str(tmp_path / "state.json")
    svc = KeyService(path, window_seconds=60.0, clock=clock)
    svc.create_key("k")
    svc.activate("k", 1)
    svc._state.reload_readonly()
    v1_doc = {key_id: [key_version_to_dict(v) for v in versions]
              for key_id, versions in svc.store._keys.items()}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(v1_doc, f)  # 写成 v1 布局：无 format 信封、无 ledger

    svc2 = KeyService(path, window_seconds=60.0, clock=clock)
    svc2._state.reload_readonly()
    assert svc2.store.active_version("k").version == 1
    req = svc2.sign("k", "GET", b"x", nonce="v1-nonce")
    res = svc2.verify(req)
    log.info("input: v1 state file -> verify ok=%s", res.ok)
    assert res.ok
    # 保存后自动升级为 v2，且流水与密钥同档
    with open(path, encoding="utf-8") as f:
        upgraded = json.load(f)
    log.info("upgraded format=%s ledger_records=%d",
             upgraded.get("format"), len(upgraded.get("ledger", [])))
    assert upgraded["format"] == STATE_FORMAT_V2
    assert len(upgraded["ledger"]) == 1


def test_sealed_archive_format_unchanged(tmp_path, clock):
    """之前导出的封存归档格式保持 kms-sealed-v1，可继续恢复。"""
    svc = KeyService(str(tmp_path / "s.json"), window_seconds=60.0, clock=clock)
    svc.create_key("k")
    svc.activate("k", 1)
    blob = svc.export("pw")
    envelope = json.loads(blob)
    log.info("export envelope format=%s kdf=%s", envelope.get("format"),
             envelope["kdf"]["algorithm"])
    assert envelope["format"] == "kms-sealed-v1"
    svc2 = KeyService(str(tmp_path / "s2.json"), window_seconds=60.0,
                      clock=clock)
    svc2.restore(blob, "pw")
    assert svc2.store.active_version("k").fingerprint() == \
        svc.store.active_version("k").fingerprint()
