"""请求流水：保留期与容量边界、审计查询与对账导出。"""
from __future__ import annotations

import hashlib
import json
import logging

from app.models import FailureReason
from app.service import KeyService

log = logging.getLogger("test.ledger")


def _mk_service(tmp_path, clock, max_records=100, retention=None):
    return KeyService(str(tmp_path / "state.json"), window_seconds=60.0,
                      clock=clock, ledger_max_records=max_records,
                      ledger_retention_seconds=retention)


def _sign_verify(service, nonce, key_id="k"):
    req = service.sign(key_id, "POST", b"payload", nonce=nonce)
    return service.verify(req)


def test_retention_window_records_never_swept_early(tmp_path, clock):
    """保留期内的记录绝不因清理被提前丢掉，重放判定不丢记录。"""
    svc = _mk_service(tmp_path, clock)
    svc.create_key("k")
    svc.activate("k", 1)
    assert _sign_verify(svc, "n1").ok
    clock.advance(30.0)  # 仍在保留期（60s）内
    swept = svc.sweep_ledger()
    log.info("input: sweep at T+30 (retention=60) -> swept=%d len=%d",
             swept, len(svc.ledger))
    assert swept == 0 and len(svc.ledger) == 1
    # 同一 nonce 重新签名（新时间戳、合法签名）仍判重
    res = _sign_verify(svc, "n1")
    log.info("input: same nonce re-signed at T+30 -> reason=%s detail=%s",
             res.reason, res.detail)
    assert res.reason == FailureReason.NONCE_REUSED


def test_capacity_full_rejects_with_distinguishable_reason(tmp_path, clock):
    """容量顶满且无保留期外记录可清理：明确拒绝，原因可区分。"""
    svc = _mk_service(tmp_path, clock, max_records=3)
    svc.create_key("k")
    svc.activate("k", 1)
    for i in range(3):
        assert _sign_verify(svc, f"n{i}").ok
    res = _sign_verify(svc, "n-overflow")
    log.info("input: 4th request with max_records=3, all in retention -> "
             "reason=%s detail=%s", res.reason, res.detail)
    assert res.reason == FailureReason.LEDGER_CAPACITY_EXCEEDED
    # 与其它失败原因可区分
    assert res.reason not in (FailureReason.NONCE_REUSED,
                              FailureReason.SIGNATURE_MISMATCH,
                              FailureReason.TIMESTAMP_OUT_OF_WINDOW)
    # 不静默丢弃：流水不增长、也不超限
    assert len(svc.ledger) == 3


def test_capacity_rejected_nonce_is_not_consumed(tmp_path, clock):
    """容量拒绝的请求不占用 nonce；腾出空间后同一请求可被受理。"""
    svc = _mk_service(tmp_path, clock, max_records=2)
    svc.create_key("k")
    svc.activate("k", 1)
    assert _sign_verify(svc, "a").ok
    assert _sign_verify(svc, "b").ok
    assert _sign_verify(svc, "c").reason == FailureReason.LEDGER_CAPACITY_EXCEEDED
    clock.advance(61.0)  # 超过保留期，旧记录可清理
    res = _sign_verify(svc, "c")
    log.info("input: retry nonce 'c' after retention expiry -> ok=%s len=%d",
             res.ok, len(svc.ledger))
    assert res.ok
    assert len(svc.ledger) == 1  # 旧记录被清理，无界增长被抑制


def test_no_unbounded_growth_under_pressure(tmp_path, clock):
    svc = _mk_service(tmp_path, clock, max_records=5)
    svc.create_key("k")
    svc.activate("k", 1)
    outcomes = {}
    for i in range(20):
        res = _sign_verify(svc, f"n{i}")
        outcomes[i] = res.reason.value if res.reason else "ok"
        clock.advance(10.0)  # 部分记录逐渐超出保留期
    log.info("input: 20 requests, max=5, advance 10s each -> %s", outcomes)
    # 不无界增长
    assert len(svc.ledger) <= 5
    # 保留期内顶满时拒绝是正确行为；旧记录过期后新请求恢复放行
    assert "ok" in outcomes.values()
    assert outcomes[19] == "ok" or len(svc.ledger) == 5
    clock.advance(61.0)  # 全部记录超出保留期
    res = _sign_verify(svc, "n-final")
    log.info("input: request after all records aged out -> ok=%s len=%d",
             res.ok, len(svc.ledger))
    assert res.ok and len(svc.ledger) == 1


def test_query_by_key_version_and_time_range(tmp_path, clock):
    svc = _mk_service(tmp_path, clock)
    svc.create_key("k")
    svc.activate("k", 1)
    svc.create_key("g")
    svc.activate("g", 1)
    t0 = clock.now
    assert _sign_verify(svc, "k-n1", "k").ok
    clock.advance(10.0)
    t1 = clock.now
    assert _sign_verify(svc, "g-n1", "g").ok
    svc.rotate("k", transition_seconds=3600.0)
    assert _sign_verify(svc, "k-n2", "k").ok  # k v2

    by_key = svc.query_ledger(key_id="k")
    by_version = svc.query_ledger(key_id="k", version=2)
    by_time = svc.query_ledger(start=t1)
    log.info("input: query key=k -> %s; key=k v=2 -> %s; start=T+10 -> %s",
             [(r.nonce, r.version) for r in by_key],
             [(r.nonce, r.version) for r in by_version],
             [(r.nonce, r.key_id) for r in by_time])
    assert {r.nonce for r in by_key} == {"k-n1", "k-n2"}
    assert [r.nonce for r in by_version] == ["k-n2"]
    assert {r.nonce for r in by_time} == {"g-n1", "k-n2"}
    # 每条记录都带结论与判定依据
    for r in by_key:
        assert r.decision == "accepted" and "signature_ok" in r.basis
        assert r.request_timestamp >= t0


def test_export_manifest_deterministic_and_offline_verifiable(tmp_path, clock):
    svc = _mk_service(tmp_path, clock)
    svc.create_key("k")
    svc.activate("k", 1)
    for i in range(3):
        assert _sign_verify(svc, f"n{i}").ok
    m1 = svc.export_ledger_manifest()
    m2 = svc.export_ledger_manifest()
    log.info("input: export twice -> identical=%s bytes=%d", m1 == m2, len(m1))
    assert m1 == m2  # 重复导出稳定可复现

    manifest = json.loads(m1)
    assert manifest["format"] == "kms-ledger-export-v1"
    assert manifest["record_count"] == 3
    # 离线可核对：按约定规则重算摘要
    canonical = json.dumps(manifest["records"], sort_keys=True,
                           separators=(",", ":"))
    assert manifest["digest"] == "sha256:" + hashlib.sha256(
        canonical.encode()).hexdigest()
    # 不含私钥明文
    assert b"PRIVATE KEY" not in m1 and b"private_key_pem" not in m1


def test_query_and_export_do_not_mutate_state(tmp_path, clock):
    svc = _mk_service(tmp_path, clock)
    svc.create_key("k")
    svc.activate("k", 1)
    assert _sign_verify(svc, "n1").ok
    before = len(svc.ledger)
    svc.query_ledger(key_id="k")
    svc.export_ledger_manifest()
    svc.query_ledger()
    log.info("input: query+export -> len before=%d after=%d", before,
             len(svc.ledger))
    assert len(svc.ledger) == before
    # 判定状态未变：重放依旧被拒
    res = _sign_verify(svc, "n1")
    assert res.reason == FailureReason.NONCE_REUSED
