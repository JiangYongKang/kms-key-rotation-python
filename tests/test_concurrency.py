"""并发一致性测试：轮转与验签并发、重复随机数并发。"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from collections import Counter

from app.signing import sign
from app.service import SignedRequest


def _signed(svc, version, ts, nonce, method="POST", path="/x", body=b""):
    req = SignedRequest(version, ts, nonce, b"", method, path, body, {})
    req.signature = sign(svc.get_key(version).private_bytes, svc._canonical(req))
    return req


def test_concurrent_duplicate_nonce_exactly_one_accepted(make_service):
    """同一签名请求（同 nonce）被 N 个线程并发校验：恰好一次接受，其余重放。"""
    svc = make_service(skew=1000)
    v = svc.create_key()
    svc.activate(v)
    req = svc.sign_request("POST", "/x", b"")

    n = 32
    barrier = threading.Barrier(n)
    results: list[tuple[bool, str | None]] = []
    lock = threading.Lock()

    def worker():
        barrier.wait()  # 尽量让所有线程同时进入判定
        dec = svc.verify_request(req)
        with lock:
            results.append((dec.accepted, dec.error_code))

    with ThreadPoolExecutor(max_workers=n) as pool:
        list(pool.map(lambda _: worker(), range(n)))

    counts = Counter(results)
    accepted = sum(1 for ok, _ in results if ok)
    replayed = sum(1 for ok, code in results if not ok and code == "NONCE_REPLAY")
    assert accepted == 1, f"同一请求被接受了 {accepted} 次: {counts}"
    assert replayed == n - 1
    # 没有任何其他错误（不能出现时间窗/签名/状态类结果）
    assert accepted + replayed == n


def test_rotate_concurrent_with_verify_consistent_verdict(make_service, clock_state):
    """轮转与验签并发时，同一已签名请求（同 nonce）的结论集合只能是：
    {接受} 或 {接受, 重放}；绝不出现密钥状态类拒绝（既通过又被拒绝）。"""
    holder, _ = clock_state
    svc = make_service(skew=1000)
    v1 = svc.create_key()
    svc.activate(v1)
    req = _signed(svc, v1, holder["t"], "race-nonce")

    n = 24
    # n 个验签线程 + 1 个轮转线程共同在屏障处集合后同时放行
    barrier = threading.Barrier(n + 1)
    results: list[str] = []
    lock = threading.Lock()

    def verify_worker():
        barrier.wait()
        dec = svc.verify_request(req)
        with lock:
            results.append("OK" if dec.accepted else (dec.error_code or "?"))

    def rotate_worker():
        barrier.wait()
        try:
            svc.rotate(transition_seconds=3600)
            with lock:
                results.append("ROTATED")
        except Exception as exc:  # 轮转本身不应失败
            with lock:
                results.append(f"ROTATE-ERR:{exc}")

    with ThreadPoolExecutor(max_workers=n + 1) as pool:
        futs = [pool.submit(verify_worker) for _ in range(n)]
        rf = pool.submit(rotate_worker)
        for f in futs:
            f.result()
        rf.result()

    # 轮转必然成功一次
    assert "ROTATED" in results
    verdicts = {r for r in results if r not in {"ROTATED"}}
    # 老版本进入 VERIFY_ONLY 且在过渡期内：只允许 OK / NONCE_REPLAY
    assert verdicts <= {"OK", "NONCE_REPLAY"}, verdicts
    assert verdicts  # 至少发生了一次验签结论
    oks = results.count("OK")
    replays = results.count("NONCE_REPLAY")
    # 同一个 nonce：接受次数恰好为 1（若有结论），其余为重放
    assert oks == 1, results
    assert oks + replays == n


def test_rotate_then_old_key_still_verifies_and_new_signs(make_service):
    """轮转落库后的稳定状态结论可解释：旧版过渡期可验签，新请求用新版。"""
    svc = make_service(skew=1000)
    v1 = svc.create_key()
    svc.activate(v1)
    v2 = svc.rotate(transition_seconds=3600)

    old_req = _signed(svc, v1, 1_000_000, "old-a")
    assert svc.verify_request(old_req).accepted
    new_req = svc.sign_request("POST", "/y", b"")
    assert new_req.version == v2
    assert svc.verify_request(new_req).accepted
