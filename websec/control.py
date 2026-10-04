"""Cooperative cancellation and one deadline for an entire scan."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field


class ScanStopped(Exception):
    """The user cancelled a scan or its total time budget expired."""


@dataclass
class ScanControl:
    max_seconds: float = 120.0
    cancelled: threading.Event = field(default_factory=threading.Event)
    started_at: float = field(default_factory=time.monotonic)

    def __post_init__(self) -> None:
        if not 1 <= self.max_seconds <= 600:
            raise ValueError("Thời gian quét tối đa phải từ 1 đến 600 giây.")

    def check(self) -> None:
        if self.cancelled.is_set():
            raise ScanStopped("Đã hủy lần quét.")
        if time.monotonic() - self.started_at >= self.max_seconds:
            raise ScanStopped("Đã hết thời gian quét tối đa.")

    def timeout(self, requested: float) -> float:
        self.check()
        # A short per-operation timeout lets cancellation interrupt slow servers.
        return max(0.05, min(requested, 5.0,
                             self.max_seconds - (time.monotonic() - self.started_at)))

    def wait(self, seconds: float) -> None:
        self.check()
        if seconds > 0:
            self.cancelled.wait(min(seconds, self.timeout(seconds)))
        self.check()
