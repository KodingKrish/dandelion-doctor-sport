"""Mock Transport Harness (Section 14): replays recorded traces so every
repair branch in the engines can be regression-tested offline, with no
physical device attached."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class MockBROM:
    """Replays the exact 2GB-Micron DRAM-init crash trace from mtkclient
    issue history, and an NVDATA-corrupted trace."""

    recorded_stderr: str = ""

    @classmethod
    def dram_setup_failed_trace(cls) -> "MockBROM":
        return cls(recorded_stderr="DRAM setup failed: unpack requires a buffer of 12 bytes")

    @classmethod
    def nvdata_corrupted_trace(cls) -> "MockBROM":
        return cls(recorded_stderr="NVDATA is corrupted")


@dataclass
class MockFastboot:
    getvar_responses: dict[str, str] = field(default_factory=dict)

    def getvar(self, name: str) -> str:
        return self.getvar_responses.get(name, "")


@dataclass
class MockADB:
    dmesg_lines: list[str] = field(default_factory=list)
    logcat_lines: list[str] = field(default_factory=list)

    def dmesg(self) -> list[str]:
        return self.dmesg_lines

    def logcat_dump(self, max_lines: int = 2000) -> list[str]:
        return self.logcat_lines[:max_lines]
