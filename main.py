"""FastAPI 入口：本地密钥签名与校验服务。"""
from __future__ import annotations

import base64
import os

from fastapi import FastAPI, HTTPException, Response
from pydantic import BaseModel

from app.keystore import IllegalTransitionError
from app.models import SignedRequest, VerifyResult
from app.service import KeyService
from app.vault import CorruptArchiveError, WrongPassphraseError

STATE_PATH = os.environ.get("KMS_STATE_PATH", "keystore_state.json")
WINDOW = float(os.environ.get("KMS_WINDOW_SECONDS", "300"))
LEDGER_RETENTION = os.environ.get("KMS_LEDGER_RETENTION_SECONDS")
LEDGER_MAX_RECORDS = int(os.environ.get("KMS_LEDGER_MAX_RECORDS", "100000"))

app = FastAPI(title="local-kms")
service = KeyService(STATE_PATH, WINDOW,
                     ledger_retention_seconds=(float(LEDGER_RETENTION)
                                               if LEDGER_RETENTION else None),
                     ledger_max_records=LEDGER_MAX_RECORDS)


class SignIn(BaseModel):
    key_id: str
    method: str
    payload_b64: str
    nonce: str | None = None


class VerifyIn(BaseModel):
    key_id: str
    version: int
    method: str
    payload_b64: str
    timestamp: float
    nonce: str
    signature_b64: str


class RotateIn(BaseModel):
    transition_seconds: float = 300.0


class ExportIn(BaseModel):
    passphrase: str


class RestoreIn(BaseModel):
    passphrase: str
    blob_b64: str


def _result_dict(res: VerifyResult) -> dict:
    return {"ok": res.ok,
            "reason": res.reason.value if res.reason else None,
            "detail": res.detail}


@app.get("/")
def read_root() -> dict:
    return {"service": "local-kms", "docs": "/docs"}


@app.post("/keys/{key_id}")
def create_key(key_id: str) -> dict:
    try:
        kv = service.create_key(key_id)
    except ValueError as exc:
        raise HTTPException(409, str(exc))
    return {"key_id": kv.key_id, "version": kv.version, "state": kv.state.value,
            "fingerprint": kv.fingerprint()}


@app.post("/keys/{key_id}/versions/{version}/activate")
def activate(key_id: str, version: int) -> dict:
    try:
        kv = service.activate(key_id, version)
    except KeyError:
        raise HTTPException(404, "key version not found")
    except IllegalTransitionError as exc:
        raise HTTPException(409, {"reason": "illegal_transition", "detail": str(exc)})
    return {"version": kv.version, "state": kv.state.value}


@app.post("/keys/{key_id}/rotate")
def rotate(key_id: str, body: RotateIn) -> dict:
    try:
        kv = service.rotate(key_id, body.transition_seconds)
    except KeyError:
        raise HTTPException(404, "key not found")
    except IllegalTransitionError as exc:
        raise HTTPException(409, {"reason": "illegal_transition", "detail": str(exc)})
    return {"version": kv.version, "state": kv.state.value,
            "fingerprint": kv.fingerprint()}


@app.post("/keys/{key_id}/versions/{version}/revoke")
def revoke(key_id: str, version: int) -> dict:
    try:
        kv = service.revoke(key_id, version)
    except KeyError:
        raise HTTPException(404, "key version not found")
    except IllegalTransitionError as exc:
        raise HTTPException(409, {"reason": "illegal_transition", "detail": str(exc)})
    return {"version": kv.version, "state": kv.state.value}


@app.post("/sign")
def sign(body: SignIn) -> dict:
    out = service.sign(body.key_id, body.method,
                       base64.b64decode(body.payload_b64), body.nonce)
    if isinstance(out, VerifyResult):
        return _result_dict(out)
    return {"ok": True, "key_id": out.key_id, "version": out.version,
            "method": out.method, "timestamp": out.timestamp, "nonce": out.nonce,
            "signature_b64": base64.b64encode(out.signature).decode()}


@app.post("/verify")
def verify(body: VerifyIn) -> dict:
    req = SignedRequest(
        method=body.method.upper(), payload=base64.b64decode(body.payload_b64),
        key_id=body.key_id, version=body.version, timestamp=body.timestamp,
        nonce=body.nonce, signature=base64.b64decode(body.signature_b64))
    return _result_dict(service.verify(req))


@app.post("/export")
def export(body: ExportIn) -> dict:
    return {"blob_b64": base64.b64encode(service.export(body.passphrase)).decode()}


@app.post("/restore")
def restore(body: RestoreIn) -> dict:
    try:
        service.restore(base64.b64decode(body.blob_b64), body.passphrase)
    except WrongPassphraseError as exc:
        raise HTTPException(403, {"reason": "wrong_passphrase", "detail": str(exc)})
    except CorruptArchiveError as exc:
        raise HTTPException(422, {"reason": "corrupt_archive", "detail": str(exc)})
    return {"ok": True}


@app.get("/ledger")
def query_ledger(key_id: str | None = None, version: int | None = None,
                 start: float | None = None, end: float | None = None) -> dict:
    """按密钥/版本/判定时间范围查询请求流水（只读）。"""
    records = service.query_ledger(key_id=key_id, version=version,
                                   start=start, end=end)
    return {"count": len(records),
            "records": [{"nonce": r.nonce, "key_id": r.key_id,
                         "version": r.version,
                         "request_timestamp": r.request_timestamp,
                         "decided_at": r.decided_at, "decision": r.decision,
                         "basis": r.basis, "reason": r.reason}
                        for r in records]}


@app.get("/ledger/export")
def export_ledger() -> Response:
    """导出离线可核对的对账清单（确定性、不含私钥）。"""
    return Response(content=service.export_ledger_manifest(),
                    media_type="application/json")


@app.post("/ledger/sweep")
def sweep_ledger() -> dict:
    """主动清理保留期外的流水记录。"""
    return {"swept": service.sweep_ledger()}
