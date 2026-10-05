"""审计查询与对账导出：过滤、结论/依据可见、只读、确定性、无私钥明文。"""
from __future__ import annotations

import json
import logging

from app.audit import AUDIT_EXPORT_FORMAT, Auditor
from app.models import FailureReason, JournalOutcome
from app.service import KeyService

log = logging.getLogger("test.audit")


def _populate(service) -> None:
    service.create_key("k")
    service.activate("k", 1)
    service.create_key("other")
    service.activate("other", 1)
    r1 = service.sign("k", "POST", b"a", nonce="k-n1")
    assert service.verify(r1).ok
    assert service.verify(r1).reason == FailureReason.NONCE_REUSED
    service.rotate("k", transition_seconds=300.0)
    r2 = service.sign("k", "POST", b"b", nonce="k-n2")
    assert service.verify(r2).ok
    ro = service.sign("other", "GET", b"c", nonce="o-n1")
    assert service.verify(ro).ok


def test_query_filters_by_key_version_and_time(service, clock):
    _populate(service)
    all_recs = service.query_records()
    log.info("input: query all -> %s",
             [(r.key_id, r.version, r.outcome.value) for r in all_recs])
    assert len(all_recs) == 4  # accept, replay, accept(k v2), accept(other)

    by_key = service.query_records(key_id="k")
    assert {r.key_id for r in by_key} == {"k"}
    assert len(by_key) == 3

    by_version = service.query_records(key_id="k", version=1)
    assert {(r.key_id, r.version) for r in by_version} == {("k", 1)}
    assert len(by_version) == 2

    t_now = clock()
    by_time = service.query_records(start=t_now - 1.0, end=t_now + 1.0)
    assert len(by_time) == 4
    assert service.query_records(start=t_now + 100.0) == []
    assert service.query_records(end=t_now - 100.0) == []

    # 每条记录都能看到结论与判定依据
    for r in all_recs:
        assert r.outcome in (JournalOutcome.ACCEPTED, JournalOutcome.REPLAYED)
        assert r.basis and r.nonce in r.basis


def test_query_does_not_mutate_state(service, clock):
    """查询与导出只读：调用前后判定状态一致。"""
    _populate(service)
    before = service.export_audit()
    recs1 = service.query_records(key_id="k")
    _ = service.export_audit()
    recs2 = service.query_records(key_id="k")
    after = service.export_audit()
    assert before == after
    assert [r.seq for r in recs1] == [r.seq for r in recs2]

    # 查询后再提交旧 nonce 仍判重复，状态未被动过
    r = service.sign("k", "GET", b"x", nonce="probe")
    assert service.verify(r).ok
    assert service.verify(r).reason == FailureReason.NONCE_REUSED
    log.info("input: query/export did not change replay verdicts")


def test_export_is_deterministic_and_has_no_private_material(service, clock):
    """重复导出字节一致、摘要可核对、不含私钥明文。"""
    _populate(service)
    b1 = service.export_audit()
    b2 = service.export_audit()
    assert b1 == b2  # 重复导出稳定可复现
    assert Auditor.digest(b1) == Auditor.digest(b2)
    assert Auditor.verify_digest(b1)

    env = json.loads(b1)
    assert env["format"] == AUDIT_EXPORT_FORMAT
    assert env["count"] == 4
    assert env["records"] == sorted(env["records"], key=lambda r: r["seq"])
    log.info("input: export digest=%s count=%d", env["digest"], env["count"])

    # 私钥相关内容绝不出现；密钥部分只有公钥指纹
    text = b1.decode("utf-8")
    assert "private_key" not in text
    for k in env["keys"]:
        assert k["private"] == "sealed"
        assert k["fingerprint"].startswith("sha256:")


def test_export_tamper_is_detectable(service):
    """清单被改动后摘要核对失败（离线可发现）。"""
    _populate(service)
    blob = service.export_audit()
    env = json.loads(blob)
    # 找到一条 accepted 记录，把结论改成 replayed
    target = next(r for r in env["records"] if r["outcome"] == "accepted")
    target["outcome"] = "replayed"
    tampered = json.dumps(env, sort_keys=True).encode("utf-8")
    assert not Auditor.verify_digest(tampered)
    log.info("input: tampered export -> digest verification fails")


def test_export_stable_after_restart(tmp_path, clock):
    """重启加载后导出与重启前一致（流水持久化、顺序稳定）。"""
    path = str(tmp_path / "state.json")
    svc = KeyService(path, window_seconds=60.0,
                     retention_seconds=60.0, nonce_capacity=1000, clock=clock)
    _populate(svc)
    before = svc.export_audit()

    reloaded = KeyService(path, window_seconds=60.0,
                          retention_seconds=60.0, nonce_capacity=1000,
                          clock=clock)
    after = reloaded.export_audit()
    assert before == after
    assert Auditor.verify_digest(after)
    log.info("input: export byte-identical across restart")
