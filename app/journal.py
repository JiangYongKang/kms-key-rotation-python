"""请求随机数流水：保留期淘汰 + 容量上限，判定可持久化、可重启恢复。

不变量：
- 保留期 ``retention_seconds`` 内已接受的 nonce 永远保留，过期记录才允许淘汰，
  因此时间窗内的重放判定绝不因清理被放行。
- 容量打满且没有任何过期记录可腾退时，新的（首次出现的）nonce 抛
  ``NonceLogFull`` 拒绝；重复 nonce 仍判重放（不新增容量占用）。
- 记录按 (recorded_at, seq) 有序保存，淘汰只切前缀，不做全表扫描。
"""
from __future__ import annotations

import bisect
import logging
import threading

from .models import AuditFilter, JournalOutcome, NonceRecord

log = logging.getLogger("kms.journal")


class NonceLogFull(Exception):
    """容量打满且保留期内记录无法腾退。"""

    def __init__(self, capacity: int, retained: int) -> None:
        self.capacity = capacity
        self.retained = retained
        super().__init__(
            f"nonce log full: capacity={capacity}, retained={retained}")


class NonceJournal:
    """随机数请求流水（纯内存结构，由 KeyStore 负责持久化）。"""

    def __init__(self, retention_seconds: float, capacity: int) -> None:
        if retention_seconds < 0:
            raise ValueError("retention_seconds must be >= 0")
        if capacity <= 0:
            raise ValueError("capacity must be > 0")
        self._lock = threading.RLock()
        self._retention = float(retention_seconds)
        self._capacity = int(capacity)
        self._records: list[NonceRecord] = []   # 按 (recorded_at, seq) 有序
        self._accepted: dict[str, NonceRecord] = {}
        self._next_seq = 1

    def bind_lock(self, lock: threading.RLock) -> None:
        self._lock = lock

    @property
    def retention_seconds(self) -> float:
        return self._retention

    @property
    def capacity(self) -> int:
        return self._capacity

    @property
    def next_seq(self) -> int:
        return self._next_seq

    def _key(self, r: NonceRecord) -> tuple[float, int]:
        return (r.recorded_at, r.seq)

    def judge(self, key_id: str, version: int, nonce: str,
              timestamp: float, now: float) -> NonceRecord:
        """判定一次携带合法签名的请求；返回流水记录（含结论与依据）。

        容量只约束“保留期内已接受的 nonce 集合”（防重放状态本身）：
        被拒重放记录不占用容量，因此重放请求无法把容量顶满来误伤合法新请求。
        """
        with self._lock:
            removed = self.evict(now)
            prior = self._accepted.get(nonce)
            if prior is not None:
                # 保留期内已接受过：重复拒绝。重放记录不占容量，容量满也照判。
                basis = (f"nonce {nonce!r} already accepted at "
                         f"{prior.recorded_at:.3f} (seq={prior.seq}); "
                         f"replayed at {now:.3f}")
                rec = self._append(
                    key_id, version, nonce, timestamp, now,
                    JournalOutcome.REPLAYED, basis)
                if removed:
                    self._note_eviction(removed)
                return rec

            if len(self._accepted) >= self._capacity:
                # evict 已尝试过：保留的已接受集合打满且没有过期记录，
                # 明确拒绝新 nonce，不静默丢弃
                raise NonceLogFull(self._capacity, len(self._accepted))

            basis = (f"nonce {nonce!r} first seen at {now:.3f} "
                     f"(request timestamp={timestamp:.3f}); accepted")
            rec = self._append(
                key_id, version, nonce, timestamp, now,
                JournalOutcome.ACCEPTED, basis)
            self._accepted[nonce] = rec
            if removed:
                self._note_eviction(removed)
            return rec

    @staticmethod
    def _note_eviction(n: int) -> None:
        log.info("evicted %d expired nonce record(s)", n)

    def _append(self, key_id: str, version: int, nonce: str, timestamp: float,
                now: float, outcome: JournalOutcome, basis: str) -> NonceRecord:
        rec = NonceRecord(seq=self._next_seq, key_id=key_id, version=version,
                          nonce=nonce, timestamp=timestamp, recorded_at=now,
                          outcome=outcome, basis=basis)
        self._next_seq += 1
        bisect.insort(self._records, rec, key=self._key)
        return rec

    def evict(self, now: float) -> int:
        """删除保留期外的记录（recorded_at < now-retention），返回删除条数。"""
        with self._lock:
            cutoff = now - self._retention
            boundary = bisect.bisect_left(
                self._records, True, key=lambda r: r.recorded_at >= cutoff)
            expired = self._records[:boundary]
            if not expired:
                return 0
            for r in expired:
                if r.outcome == JournalOutcome.ACCEPTED:
                    # 仅当映射仍指向这条记录时才删除（nonce 全局只接受一次）
                    if self._accepted.get(r.nonce) is r:
                        del self._accepted[r.nonce]
            del self._records[:boundary]
            return len(expired)

    def query(self, flt: AuditFilter | None = None) -> list[NonceRecord]:
        with self._lock:
            return self._filter(flt)

    def _filter(self, flt: AuditFilter | None) -> list[NonceRecord]:
        out = []
        for r in self._records:
            if flt is not None:
                if flt.key_id is not None and r.key_id != flt.key_id:
                    continue
                if flt.version is not None and r.version != flt.version:
                    continue
                if flt.start is not None and r.recorded_at < flt.start:
                    continue
                if flt.end is not None and r.recorded_at > flt.end:
                    continue
            out.append(NonceRecord(**r.__dict__))
        out.sort(key=lambda r: r.seq)
        return out

    def load_state(self, records: list[NonceRecord], next_seq: int = 0) -> None:
        """从磁盘恢复：重建有序记录与保留期内的 accepted 索引。"""
        with self._lock:
            ordered = sorted(records, key=lambda r: (r.recorded_at, r.seq))
            self._records = ordered
            self._accepted = {}
            max_seq = 0
            for r in ordered:
                max_seq = max(max_seq, r.seq)
                if r.outcome == JournalOutcome.ACCEPTED and r.nonce not in self._accepted:
                    self._accepted[r.nonce] = r
            self._next_seq = max(next_seq, max_seq + 1, 1)

    def dump_state(self) -> list[NonceRecord]:
        with self._lock:
            return [NonceRecord(**r.__dict__)
                    for r in sorted(self._records, key=lambda r: r.seq)]

    def __len__(self) -> int:
        with self._lock:
            return len(self._records)
