"""FastAPI 入口：在既有 Hello World 服务上扩展本地密钥签名能力。

状态文件默认 kms_state.json（可用环境变量 LOCAL_KMS_STATE 指定），
二进制 body/signature 在 JSON 中以 base64 传输。
"""

from __future__ import annotations

import base64
import os
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.errors import KeyServiceError
from app.keys import KeyState
from app.sealing import Seal
from app.service import KeyService

app = FastAPI(title="local-kms-key-rotation")

_service: Optional[KeyService] = None


def get_service() -> KeyService:
    global _service
    if _service is None:
        _service = KeyService(os.environ.get("LOCAL_KMS_STATE", "kms_state.json"))
    return _service


@app.exception_handler(KeyServiceError)
def handle_key_service_error(_request: Request, exc: KeyServiceError) -> JSONResponse:
    return JSONResponse(status_code=400, content={"error": exc.code.value, "reason": exc.reason})


class SignIn(BaseModel):
    method: str = "POST"
    path: str = "/"
    body_b64: str = ""
    headers: dict[str, str] = Field(default_factory=dict)


class VerifyIn(BaseModel):
    version: int
    timestamp: int
    nonce: str
    signature_b64: str
    method: str
    path: str
    body_b64: str = ""
    headers: dict[str, str] = Field(default_factory=dict)


class TransitionIn(BaseModel):
    target: KeyState
    verify_until: Optional[int] = None


class PasswordIn(BaseModel):
    password: str


class RestoreIn(BaseModel):
    password: str
    seal: str


@app.get("/")
def read_root():
    return {"Hello": "World"}


@app.post("/keys")
def create_key():
    return {"version": get_service().create_key()}


@app.post("/keys/{version}/activate")
def activate_key(version: int):
    get_service().activate(version)
    return {"version": version, "state": KeyState.ACTIVE.value}


@app.post("/rotate")
def rotate_key(transition_seconds: int = 86400):
    v = get_service().rotate(transition_seconds)
    return {"version": v}


@app.post("/keys/{version}/revoke")
def revoke_key(version: int):
    get_service().revoke(version)
    return {"version": version, "state": KeyState.REVOKED.value}


@app.post("/keys/{version}/transition")
def transition_key(version: int, data: TransitionIn):
    get_service().transition(version, data.target, data.verify_until)
    return {"version": version, "state": data.target.value}


@app.get("/keys")
def list_keys():
    return {"keys": get_service().list_versions()}


@app.post("/sign")
def sign_request(data: SignIn):
    req = get_service().sign_request(
        data.method, data.path, base64.b64decode(data.body_b64), data.headers
    )
    return {
        "version": req.version,
        "timestamp": req.timestamp,
        "nonce": req.nonce,
        "signature_b64": base64.b64encode(req.signature).decode("ascii"),
        "method": req.method,
        "path": req.path,
        "body_b64": base64.b64encode(req.body).decode("ascii"),
        "headers": req.headers,
    }


@app.post("/verify")
def verify_request(data: VerifyIn):
    from app.service import SignedRequest

    req = SignedRequest(
        version=data.version,
        timestamp=data.timestamp,
        nonce=data.nonce,
        signature=base64.b64decode(data.signature_b64),
        method=data.method,
        path=data.path,
        body=base64.b64decode(data.body_b64),
        headers=data.headers,
    )
    decision = get_service().verify_request(req)
    return {
        "accepted": decision.accepted,
        "error": decision.error_code,
        "reason": decision.reason,
    }


@app.post("/seal/export")
def export_seal(data: PasswordIn):
    seal = get_service().export_sealed(data.password)
    return {"seal": seal.to_json()}


@app.post("/seal/restore")
def restore_seal(data: RestoreIn):
    get_service().restore_sealed(Seal.from_json(data.seal), data.password)
    return {"restored": True, "keys": get_service().list_versions()}
