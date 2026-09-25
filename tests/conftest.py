"""pytest 公共夹具。

通过 logging 将“输入 + 判定依据”输出到单测日志（service 内部已记录），
pytest 配置开启 log_cli，运行时可直接看到每个判定的输入与原因。
"""

from __future__ import annotations

import logging
import os
import tempfile

import pytest

from app.service import KeyService


@pytest.fixture
def clock_state():
    """可变时钟：返回 (当前秒值的持有者, 修改函数)。"""
    holder = {"t": 1_000_000}
    return holder, (lambda t: holder.__setitem__("t", t))


@pytest.fixture
def make_service(clock_state):
    holder, set_t = clock_state

    def _make(skew: int = 300, retention: int = 3600) -> KeyService:
        tmp_dir = tempfile.mkdtemp(prefix="kms-test-")
        return KeyService(
            state_path=os.path.join(tmp_dir, "state.json"),
            clock=lambda: holder["t"],
            skew_seconds=skew,
            nonce_retention_seconds=retention,
        )

    return _make


@pytest.fixture(autouse=True)
def _emit_case_banner(request):
    logging.getLogger("tests").info(
        "====== 用例开始 %s ======", request.node.nodeid
    )
    yield
