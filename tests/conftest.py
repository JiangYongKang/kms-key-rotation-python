"""测试公共夹具：可控时钟 + 临时状态目录。"""
from __future__ import annotations

import pytest

from app.service import KeyService


class FakeClock:
    """可手动推进的时钟，保证测试离线可复现。"""

    def __init__(self, start: float = 1_000_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> float:
        self.now += seconds
        return self.now


@pytest.fixture()
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture()
def service(tmp_path, clock) -> KeyService:
    return KeyService(str(tmp_path / "state.json"), window_seconds=60.0,
                      clock=clock)
