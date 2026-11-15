"""BROM / Preloader / DA transport (Section 6, 9.2, 9.3).

dandelion-doctor does not reimplement MediaTek BootROM exploitation.
Per Section 4.1 ("Low-Level MediaTek Transport: bkerler/mtkclient Python API
+ Kamakiri2 + EMI Preloader Injector"), this module is a thin, auditable
wrapper around the `mtk` CLI provided by the mtkclient project
(https://github.com/bkerler/mtkclient), which the operator installs
separately. Every call is logged by the caller via AuditLogger before any
partition is touched, and every destructive call must first pass
SafetyGatekeeper.preflight().
"""
from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


class MtkClientNotFound(RuntimeError):
    pass


@dataclass
class BromResult:
    returncode: int
    stdout: str
    stderr: str


@dataclass
class BromHandshake:
    cpu: str | None = None
    hw_subcode: str | None = None
    hw_ver: str | None = None
    me_id_hex: str | None = None
    soc_id_hex: str | None = None


_ME_ID_RE = re.compile(r"ME_ID:\s*([0-9A-Fa-f]+)")
_SOC_ID_RE = re.compile(r"SOC_ID:\s*([0-9A-Fa-f]+)")
_SUBCODE_RE = re.compile(r"HW subcode:\s*(0x[0-9A-Fa-f]+)")
_HWVER_RE = re.compile(r"HW Ver:\s*(0x[0-9A-Fa-f]+)")
_CPU_RE = re.compile(r"CPU:\s*([\w/]+(?:\([^)]*\))?)")


class BromClient:
    """Wraps `python mtk ...` from an installed mtkclient checkout."""

    def __init__(self, mtk_bin: str = "mtk", preloader: Path | None = None):
        self.mtk_bin = mtk_bin
        self.preloader = preloader
        if shutil.which(mtk_bin) is None:
            raise MtkClientNotFound(
                "mtkclient 'mtk' entrypoint not found on PATH. "
                "Install it per https://github.com/bkerler/mtkclient and ensure it is importable."
            )

    def _base_args(self) -> list[str]:
        args = [self.mtk_bin]
        if self.preloader is not None:
            args += ["--preloader", str(self.preloader)]
        return args

    def _run(self, *args: str, timeout: float = 120.0) -> BromResult:
        proc = subprocess.run([*self._base_args(), *args], capture_output=True, text=True, timeout=timeout)
        return BromResult(proc.returncode, proc.stdout, proc.stderr)

    def handshake(self) -> BromHandshake:
        """Reads CPU identity, HW subcode/ver, ME_ID and SOC_ID (Section 2.1)
        without writing anything — used by SafetyGatekeeper.bind_identity()."""
        result = self._run("printgpt")
        blob = result.stdout + result.stderr
        return BromHandshake(
            cpu=(m.group(1) if (m := _CPU_RE.search(blob)) else None),
            hw_subcode=(m.group(1) if (m := _SUBCODE_RE.search(blob)) else None),
            hw_ver=(m.group(1) if (m := _HWVER_RE.search(blob)) else None),
            me_id_hex=(m.group(1) if (m := _ME_ID_RE.search(blob)) else None),
            soc_id_hex=(m.group(1) if (m := _SOC_ID_RE.search(blob)) else None),
        )

    def dump_partition(self, name: str, out_path: Path, parttype: str = "user") -> BromResult:
        return self._run("r", name, str(out_path), f"--parttype={parttype}", timeout=300.0)

    def write_partition(self, name: str, image_path: Path, parttype: str = "user") -> BromResult:
        # Caller must have verified SafetyGatekeeper.preflight() + partition tier.
        return self._run("w", name, str(image_path), f"--parttype={parttype}", timeout=300.0)

    def read_full_flash(self, out_path: Path) -> BromResult:
        return self._run("rf", str(out_path), timeout=1800.0)

    def seccfg(self, flag: str) -> BromResult:
        """flag is 'unlock' or 'lock'. seccfg is Tier-1 Golden-Vault; caller
        must snapshot it first (Section 9.3)."""
        return self._run("da", "seccfg", flag, timeout=60.0)

    def crash_to_brom(self, payload: Path) -> BromResult:
        """Kamakiri2 SLA/DAA bypass (Section 9.2, FIX-00361 family)."""
        return self._run("payload", "--payload", str(payload), timeout=30.0)
