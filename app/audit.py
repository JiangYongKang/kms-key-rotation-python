"""请求流水查询与离线对账清单导出（只读，不改变任何判定状态）。"""
from __future__ import annotations

import hashlib
import json

from .models import AuditFilter, KeyVersion, NonceRecord

AUDIT_EXPORT_FORMAT = "kms-audit-v1"


class Auditor:
    """只读审计：按条件过滤流水、导出确定性的对账清单。

    确定性保证：
    - 记录按全局单调 seq 排序，key_id/version 等维度稳定；
    - JSON 序列化 sort_keys=True、无随机字段；
    - 同一底层状态下重复导出得到字节完全一致的结果，可离线核对摘要。
    导出只含公钥指纹等非敏感字段，绝不包含私钥明文。
    """

    @staticmethod
    def query(records: list[NonceRecord],
              flt: AuditFilter | None = None) -> list[NonceRecord]:
        out = []
        for r in records:
            if flt is not None:
                if flt.key_id is not None and r.key_id != flt.key_id:
                    continue
                if flt.version is not None and r.version != flt.version:
                    continue
                if flt.start is not None and r.recorded_at < flt.start:
                    continue
                if flt.end is not None and r.recorded_at > flt.end:
                    continue
            out.append(r)
        return sorted(out, key=lambda r: r.seq)

    @staticmethod
    def _record_dict(r: NonceRecord) -> dict:
        return {
            "seq": r.seq,
            "key_id": r.key_id,
            "version": r.version,
            "nonce": r.nonce,
            "timestamp": r.timestamp,
            "recorded_at": r.recorded_at,
            "outcome": r.outcome.value,
            "basis": r.basis,
        }

    @staticmethod
    def _key_dict(v: KeyVersion) -> dict:
        # 仅暴露公钥指纹；private_key 字段显式封存，不出现私钥明文
        return {
            "key_id": v.key_id,
            "version": v.version,
            "state": v.state.value,
            "fingerprint": v.fingerprint(),
            "created_at": v.created_at,
            "activated_at": v.activated_at,
            "verify_only_until": v.verify_only_until,
            "revoked_at": v.revoked_at,
            "predecessor_version": v.predecessor_version,
            "private": "sealed",
        }

    def export(self, records: list[NonceRecord],
               versions: list[KeyVersion]) -> bytes:
        entries = [self._record_dict(r) for r in sorted(records, key=lambda r: r.seq)]
        keys = [self._key_dict(v) for v in sorted(
            versions, key=lambda v: (v.key_id, v.version))]
        body = {
            "format": AUDIT_EXPORT_FORMAT,
            "keys": keys,
            "records": entries,
            "count": len(entries),
        }
        # 摘要覆盖规范序列化后的正文；外层 JSON 同样确定性序列化
        body["digest"] = "sha256:" + hashlib.sha256(
            json.dumps(body, sort_keys=True, separators=(",", ":"))
            .encode("utf-8")).hexdigest()
        return json.dumps(body, sort_keys=True, indent=2).encode("utf-8")

    @staticmethod
    def digest(blob: bytes) -> str:
        return "sha256:" + hashlib.sha256(blob).hexdigest()

    @staticmethod
    def verify_digest(blob: bytes) -> bool:
        """离线核对：重新计算正文摘要，与清单内 digest 字段比对。"""
        envelope = json.loads(blob.decode("utf-8"))
        claimed = envelope.get("digest")
        body = {k: v for k, v in envelope.items() if k != "digest"}
        actual = "sha256:" + hashlib.sha256(
            json.dumps(body, sort_keys=True, separators=(",", ":"))
            .encode("utf-8")).hexdigest()
        return claimed == actual
