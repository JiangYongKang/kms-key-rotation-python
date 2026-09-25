"""FastAPI HTTP 层端到端测试（离线 TestClient）。"""

from __future__ import annotations

import base64
import importlib
import os

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path, monkeypatch):
    state_file = tmp_path / "http_state.json"
    monkeypatch.setenv("LOCAL_KMS_STATE", str(state_file))
    import main

    importlib.reload(main)  # 重新初始化单例以指向临时状态
    main._service = None
    return TestClient(main.app)


def test_root_ok(client):
    assert client.get("/").json() == {"Hello": "World"}


def test_full_lifecycle_and_verify_flow(client):
    v = client.post("/keys").json()["version"]
    assert client.post(f"/keys/{v}/activate").status_code == 200

    body = base64.b64encode(b'{"amount":42}').decode()
    signed = client.post(
        "/sign",
        json={"method": "POST", "path": "/pay", "body_b64": body, "headers": {"X-App": "demo"}},
    ).json()
    assert signed["version"] == v

    decision = client.post("/verify", json=signed).json()
    assert decision["accepted"] is True and decision["error"] is None

    replay = client.post("/verify", json=signed).json()
    assert replay["accepted"] is False and replay["error"] == "NONCE_REPLAY"


def test_rotate_and_revoke_over_http(client):
    v1 = client.post("/keys").json()["version"]
    client.post(f"/keys/{v1}/activate")
    v2 = client.post("/rotate?transition_seconds=600").json()["version"]

    listing = {k["version"]: k for k in client.get("/keys").json()["keys"]}
    assert listing[v1]["state"] == "VERIFY_ONLY"
    assert listing[v2]["state"] == "ACTIVE" and listing[v2]["current"] is True

    assert client.post(f"/keys/{v1}/revoke").status_code == 200
    # 重复吊销 -> 可区分错误码
    r = client.post(f"/keys/{v1}/revoke")
    assert r.status_code == 400 and r.json()["error"] == "ILLEGAL_TRANSITION"


def test_bad_signature_distinct_error(client):
    v = client.post("/keys").json()["version"]
    client.post(f"/keys/{v}/activate")
    signed = client.post(
        "/sign", json={"method": "POST", "path": "/x", "body_b64": ""}
    ).json()
    signed["signature_b64"] = base64.b64encode(b"\x00" * 64).decode()
    r = client.post("/verify", json=signed).json()
    assert r["accepted"] is False and r["error"] == "SIGNATURE_MISMATCH"


def test_seal_export_restore_wrong_password(client):
    v = client.post("/keys").json()["version"]
    client.post(f"/keys/{v}/activate")
    seal = client.post("/seal/export", json={"password": "secret"}).json()["seal"]

    r = client.post("/seal/restore", json={"password": "wrong", "seal": seal})
    assert r.status_code == 400 and r.json()["error"] == "BAD_PASSWORD"

    r = client.post("/seal/restore", json={"password": "secret", "seal": seal})
    assert r.status_code == 200 and r.json()["restored"] is True
