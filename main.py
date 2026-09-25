"""FastAPI 入口：本地密钥签名与校验服务。"""
from __future__ import annotations

import base64
import os

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from app.keystore import IllegalTransitionError
from app.models import SignedRequest, VerifyResult
from app.service import KeyService
from app.vault import CorruptArchiveError, WrongPassphraseError

STATE_PATH = os.environ.get("KMS_STATE_PATH", "keystore_state.json")
WINDOW = float(os.environ.get("KMS_WINDOW_SECONDS", "300"))

app = FastAPI(title="local-kms")
service = KeyService(STATE_PATH, WINDOW)


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
