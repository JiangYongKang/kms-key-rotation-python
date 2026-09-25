"""请求签名、时间窗偏移与重放防护测试。"""

from __future__ import annotations

from app.signing import sign
from app.service import SignedRequest


def rewire_signature(svc, req, version=None):
    v = version if version is not None else req.version
    req.signature = sign(svc.get_key(v).private_bytes, svc._canonical(req))
    return req


def make_active(svc):
    v = svc.create_key()
    svc.activate(v)
    return v


def test_valid_request_accepted_and_logs_input(make_service, clock_state, caplog):
    holder, _ = clock_state
    svc = make_service(skew=10)
    make_active(svc)
    with caplog.at_level("INFO", logger="app.service"):
        req = svc.sign_request("post", "/pay", b'{"amount":1}', {"X-Trace": "abc"})
        dec = svc.verify_request(req)
    assert dec.accepted
    # 单测日志中必须出现输入要素与判定依据
    log_text = caplog.text
    assert "verify_request 输入=" in log_text
    assert "nonce=" in log_text
    assert "判定=接受" in log_text


def test_skew_too_old_boundary(make_service, clock_state):
    holder, set_t = clock_state
    svc = make_service(skew=10)
    v = make_active(svc)
    t0 = holder["t"]

    # 恰好在下界（含）：ts = t0-10 接受
    req = svc.sign_request("GET", "/", b"")
    req.timestamp = t0 - 10
    req.nonce = "bound-old-ok"
    rewire_signature(svc, req)
    assert svc.verify_request(req).accepted

    # 早 1 秒越界：SKEW_TOO_OLD（与签名错误可区分）
    req.timestamp = t0 - 11
    req.nonce = "bound-old-bad"
    rewire_signature(svc, req)
    dec = svc.verify_request(req)
    assert (dec.accepted, dec.error_code) == (False, "SKEW_TOO_OLD")


def test_skew_in_future(make_service, clock_state):
    holder, set_t = clock_state
    svc = make_service(skew=10)
    v = make_active(svc)
    t0 = holder["t"]

    req = svc.sign_request("GET", "/", b"")
    req.timestamp = t0 + 11
    req.nonce = "future-bad"
    rewire_signature(svc, req)
    dec = svc.verify_request(req)
    assert (dec.accepted, dec.error_code) == (False, "SKEW_IN_FUTURE")

    # 时钟前推，时间窗通过但 nonce 已被记录过? —— 这里换一个新 nonce 验证上界包含
    req.timestamp = t0 + 10
    req.nonce = "future-ok"
    rewire_signature(svc, req)
    assert svc.verify_request(req).accepted


def test_signature_mismatch_distinguishes_tampering(make_service, clock_state):
    holder, _ = clock_state
    svc = make_service(skew=10)
    make_active(svc)

    # 改方法
    req = svc.sign_request("POST", "/x", b"data")
    req.method = "GET"
    assert svc.verify_request(req).error_code == "SIGNATURE_MISMATCH"

    # 改负载
    req2 = svc.sign_request("POST", "/x", b"data")
    req2.body = b"datA"
    assert svc.verify_request(req2).error_code == "SIGNATURE_MISMATCH"

    # 改路径
    req3 = svc.sign_request("POST", "/x", b"data")
    req3.path = "/y"
    assert svc.verify_request(req3).error_code == "SIGNATURE_MISMATCH"

    # 垃圾签名
    req4 = svc.sign_request("POST", "/x", b"data")
    req4.signature = b"not-a-signature"
    assert svc.verify_request(req4).error_code == "SIGNATURE_MISMATCH"


def test_nonce_replay_rejected_and_distinct(make_service):
    svc = make_service(skew=1000)
    make_active(svc)
    req = svc.sign_request("POST", "/x", b"")
    assert svc.verify_request(req).accepted
    dec = svc.verify_request(req)  # 完全相同的请求
    assert (dec.accepted, dec.error_code) == (False, "NONCE_REPLAY")
    assert "已于" in dec.reason and "重放" in dec.reason


def test_nonce_records_evicted_after_retention(make_service, clock_state):
    holder, set_t = clock_state
    svc = make_service(skew=1000, retention=60)
    v = make_active(svc)
    t0 = holder["t"]

    req = svc.sign_request("POST", "/x", b"")
    assert svc.verify_request(req).accepted
    assert req.nonce in svc.state.nonces

    # 超过保留期后，下一次判定先淘汰流水：旧 nonce 不再占内存
    set_t(t0 + 61)
    other = svc.sign_request("POST", "/x", b"")  # 触发 prune
    assert req.nonce not in svc.state.nonces
    assert svc.verify_request(other).accepted

    # 淘汰后旧请求带旧时间戳已超出时间窗（SKEW_TOO_OLD），
    # 用当前时间戳重签并复用旧 nonce：因流水已被淘汰，应被当作新请求接受
    req.timestamp = holder["t"]
    req.nonce = req.nonce  # 同一个旧 nonce 字符串
    rewire_signature(svc, req)
    dec = svc.verify_request(req)
    assert dec.accepted, dec


def test_nonce_store_bounded_under_many_requests(make_service, clock_state):
    holder, set_t = clock_state
    svc = make_service(skew=10**9, retention=100)
    make_active(svc)
    for i in range(50):
        set_t(1_000_000 + i * 1000)
        r = svc.sign_request("POST", "/x", b"")
        assert svc.verify_request(r).accepted
    # retention=100s：只保留最近窗口内少量 nonce，而不是 50 条
    assert len(svc.state.nonces) <= 2
