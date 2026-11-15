"""Fastboot / fastbootd transport wrapper (Section 6, 9.3, 9.4)."""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass


class FastbootNotFound(RuntimeError):
    pass


@dataclass
class FastbootResult:
    returncode: int
    stdout: str
    stderr: str


class FastbootClient:
    def __init__(self, serial: str, fastboot_path: str = "fastboot"):
        self.serial = serial
        self.fastboot_path = fastboot_path
        if shutil.which(fastboot_path) is None:
            raise FastbootNotFound(
                f"'{fastboot_path}' not found on PATH. Install platform-tools into assets/platform-tools/."
            )

    def _run(self, *args: str, timeout: float = 60.0) -> FastbootResult:
        proc = subprocess.run(
            [self.fastboot_path, "-s", self.serial, *args],
            capture_output=True, text=True, timeout=timeout,
        )
        return FastbootResult(proc.returncode, proc.stdout.strip(), proc.stderr.strip())

    def getvar(self, name: str) -> str:
        # fastboot prints getvar output to stderr historically; check both.
        result = self._run("getvar", name)
        blob = result.stderr or result.stdout
        for line in blob.splitlines():
            if line.startswith(f"{name}:"):
                return line.split(":", 1)[1].strip()
        return ""

    def is_unlocked(self) -> bool:
        return self.getvar("unlocked").lower() == "yes"

    def reboot_fastbootd(self) -> FastbootResult:
        return self._run("reboot", "fastboot")

    def reboot(self) -> FastbootResult:
        return self._run("reboot")

    def flash(self, partition: str, image_path: str, timeout: float = 300.0) -> FastbootResult:
        # Caller MUST have already passed SafetyGatekeeper.preflight() and
        # the partition-tier check in core/scatter.py before calling this.
        return self._run("flash", partition, image_path, timeout=timeout)

    def erase(self, partition: str) -> FastbootResult:
        return self._run("erase", partition)

    def set_active(self, slot: str) -> FastbootResult:
        return self._run("set_active", slot)
