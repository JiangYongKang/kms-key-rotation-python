"""请求流水：重放判定、保留期/容量策略、审计查询与对账导出。

策略要点：
- 保留期内（``decided_at >= now - retention_seconds``）的记录绝不因清理
  被提前删除，保证窗口内的重放判定不丢记录。
- 容量顶到 ``max_records`` 且清理不出保留期外的记录时，抛
  :class:`CapacityExceededError`，由上层转成可区分的拒绝原因
  （``ledger_capacity_exceeded``），不静默丢弃、不无界增长。
- 清理是 O(n) 的惰性过滤，随记录动作摊销，不长时间卡住签名/验签。
- 查询与导出为纯只读，不改变任何判定状态。
"""
from __future__ import annotations

import hashlib
import json
import threading

from .models import LedgerConfig, LedgerRecord
from .state import ledger_record_to_dict

EXPORT_FORMAT = "kms-ledger-export-v1"


class CapacityExceededError(Exception):
    """容量已满且保留期内无可清理记录：新请求必须被拒绝。"""

    def __init__(self, max_records: int) -> None:
        self.max_records = max_records
        super().__init__(
            f"ledger capacity {max_records} reached and no records "
            f"older than retention window can be evicted")


class RequestLedger:
    """已受理请求的流水记录集合：重放判定 + 审计对账。"""

    def __init__(self, config: LedgerConfig,
                 records: list[LedgerRecord] | None = None) -> None:
        self._lock = threading.Lock()
        self._config = config
        self._records: list[LedgerRecord] = records if records is not None else []

    # ---- 重放判定与记录 --------------------------------------------------
    def check_and_record(self, record: LedgerRecord, now: float) -> bool:
        """nonce 未见过则记录并返回 True；重复返回 False。

        记录前先惰性清理保留期外的记录；清理后仍顶到容量上限则抛
        CapacityExceededError（调用方必须把该请求整体拒绝）。
        """
        with self._lock:
            self._sweep_locked(now)
            if any(r.nonce == record.nonce for r in self._records):
                return False
            if len(self._records) >= self._config.max_records:
                raise CapacityExceededError(self._config.max_records)
            self._records.append(record)
            return True

    def has_nonce(self, nonce: str) -> bool:
        with self._lock:
            return any(r.nonce == nonce for r in self._records)

    def sweep(self, now: float) -> int:
        """清理保留期外的记录，返回清理条数；保留期内记录绝不动。"""
        with self._lock:
            return self._sweep_locked(now)

    def _sweep_locked(self, now: float) -> int:
        cutoff = now - self._config.retention_seconds
        before = len(self._records)
        self._records[:] = [r for r in self._records if r.decided_at >= cutoff]
        return before - len(self._records)

    # ---- 审计查询（只读） ------------------------------------------------
    def query(self, key_id: str | None = None, version: int | None = None,
              start: float | None = None, end: float | None = None
              ) -> list[LedgerRecord]:
        """按密钥/版本/判定时间范围过滤；返回副本，不改变任何状态。"""
        with self._lock:
            return [r for r in self._records
                    if (key_id is None or r.key_id == key_id)
                    and (version is None or r.version == version)
                    and (start is None or r.decided_at >= start)
                    and (end is None or r.decided_at <= end)]

    # ---- 对账导出（只读、确定性） ----------------------------------------
    def export_manifest(self) -> bytes:
        """导出离线可核对的对账清单。

        不含任何私钥材料；记录按 (decided_at, nonce) 排序、键序固定，
        重复导出字节完全一致；附 sha256 摘要便于离线校验。
        """
        with self._lock:
            records = sorted((ledger_record_to_dict(r) for r in self._records),
                             key=lambda d: (d["decided_at"], d["nonce"]))
        canonical = json.dumps(records, sort_keys=True, separators=(",", ":"))
        manifest = {
            "format": EXPORT_FORMAT,
            "record_count": len(records),
            "digest": "sha256:" + hashlib.sha256(
                canonical.encode("utf-8")).hexdigest(),
            "records": records,
        }
        return json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")

    def __len__(self) -> int:
        with self._lock:
            return len(self._records)
