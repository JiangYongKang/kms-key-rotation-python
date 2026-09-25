"""本地状态持久化：密钥版本、当前版本、请求流水(nonce)。

状态以 JSON 文件保存（离线可复现）。nonce 记录带“首次出现时间戳”，
按保留窗口淘汰，长期运行不会无界增长。写入采用临时文件 + os.replace
原子替换，避免半写文件。
"""

from __future__ import annotations

import base64
import dataclasses
import json
import os
import tempfile
from typing import Optional

from app.errors import ErrorCode, KeyServiceError


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text, validate=True)


@dataclasses.dataclass
class StoredKey:
    version: int
    public_b64: str
    private_b64: str
    state: str
    created_at: int
    verify_until: Optional[int] = None

    def to_json(self) -> dict[str, object]:
        return dataclasses.asdict(self)

    @classmethod
    def from_json(cls, data: dict[str, object]) -> "StoredKey":
        try:
            return cls(
                version=int(data["version"]),
                public_b64=str(data["public_b64"]),
                private_b64=str(data["private_b64"]),
                state=str(data["state"]),
                created_at=int(data["created_at"]),
                verify_until=(None if data.get("verify_until") is None else int(data["verify_until"])),
            )
        except (KeyError, ValueError, TypeError) as exc:
            raise KeyServiceError(ErrorCode.STATE_CORRUPT, "本地密钥记录字段损坏") from exc


@dataclasses.dataclass
class LocalState:
    path: str
    current_version: Optional[int] = None
    keys: dict[int, StoredKey] = dataclasses.field(default_factory=dict)
    nonces: dict[str, int] = dataclasses.field(default_factory=dict)

    def save(self) -> None:
        payload = {
            "current_version": self.current_version,
            "keys": {str(v): k.to_json() for v, k in sorted(self.keys.items())},
            "nonces": dict(sorted(self.nonces.items())),
        }
        directory = os.path.dirname(os.path.abspath(self.path)) or "."
        fd, tmp = tempfile.mkstemp(prefix=".kms_state.", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(payload, f, sort_keys=True, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    @classmethod
    def load(cls, path: str) -> "LocalState":
        state = cls(path=path)
        if not os.path.exists(path):
            return state
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            state.current_version = (
                None if data.get("current_version") is None else int(data["current_version"])
            )
            for key, raw in data["keys"].items():
                sk = StoredKey.from_json(raw)
                if sk.version != int(key):
                    raise KeyServiceError(ErrorCode.STATE_CORRUPT, "密钥版本号与键不一致")
                state.keys[sk.version] = sk
            for nonce, ts in data.get("nonces", {}).items():
                state.nonces[str(nonce)] = int(ts)
        except KeyServiceError:
            raise
        except (ValueError, TypeError, KeyError, OSError) as exc:
            raise KeyServiceError(ErrorCode.STATE_CORRUPT, f"本地状态文件损坏: {exc}") from exc
        return state

    def prune_nonces(self, now: int, retention_seconds: int) -> int:
        """淘汰 first_seen <= now-retention_seconds 的 nonce，返回淘汰数量。"""
        horizon = now - retention_seconds
        stale = [n for n, ts in self.nonces.items() if ts <= horizon]
        for n in stale:
            del self.nonces[n]
        return len(stale)

    # ---- 密钥材料读写便捷方法 ----
    def put_key(
        self,
        version: int,
        public_bytes: bytes,
        private_bytes: bytes,
        state: str,
        created_at: int,
        verify_until: Optional[int],
    ) -> None:
        self.keys[version] = StoredKey(
            version=version,
            public_b64=_b64e(public_bytes),
            private_b64=_b64e(private_bytes),
            state=state,
            created_at=created_at,
            verify_until=verify_until,
        )

    def public_bytes(self, version: int) -> bytes:
        return _b64d(self.keys[version].public_b64)

    def private_bytes(self, version: int) -> bytes:
        return _b64d(self.keys[version].private_b64)
