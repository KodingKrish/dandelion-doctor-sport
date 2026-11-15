"""ADB transport wrapper (Section 6, 9.1).

Thin, auditable wrapper around the pinned `adb` platform-tools binary.
Every invocation is funneled through AuditLogger by the caller.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass


class AdbNotFound(RuntimeError):
    pass


@dataclass
class AdbResult:
    returncode: int
    stdout: str
    stderr: str


class AdbClient:
    def __init__(self, serial: str, adb_path: str = "adb"):
        self.serial = serial
        self.adb_path = adb_path
        if shutil.which(adb_path) is None:
            raise AdbNotFound(
                f"'{adb_path}' not found on PATH. Install platform-tools into assets/platform-tools/ "
                "and add it to PATH, or pass an explicit adb_path."
            )

    def _run(self, *args: str, timeout: float = 30.0) -> AdbResult:
        proc = subprocess.run(
            [self.adb_path, "-s", self.serial, *args],
            capture_output=True, text=True, timeout=timeout,
        )
        return AdbResult(proc.returncode, proc.stdout.strip(), proc.stderr.strip())

    def get_serialno(self) -> str:
        return self._run("get-serialno").stdout

    def shell(self, command: str, timeout: float = 30.0) -> AdbResult:
        return self._run("shell", command, timeout=timeout)

    def getprop(self, prop: str) -> str:
        return self.shell(f"getprop {prop}").stdout

    def reboot(self, target: str | None = None) -> AdbResult:
        return self._run("reboot", *(filter(None, [target])))

    def pull(self, remote: str, local: str, timeout: float = 120.0) -> AdbResult:
        return self._run("pull", remote, local, timeout=timeout)

    def push(self, local: str, remote: str, timeout: float = 120.0) -> AdbResult:
        return self._run("push", local, remote, timeout=timeout)

    def dmesg(self) -> list[str]:
        return self.shell("dmesg").stdout.splitlines()

    def logcat_dump(self, max_lines: int = 2000) -> list[str]:
        result = self._run("logcat", "-d", "-t", str(max_lines))
        return result.stdout.splitlines()
