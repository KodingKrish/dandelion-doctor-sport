"""META Mode transport (0E8D:2007) — Section 6, 9.6.

Used only for restoring this unit's OWN original factory identifiers
(Section 2.4). dandelion-doctor never writes an identifier here unless
SafetyGatekeeper.identifier_operation_allowed() returns True for the
requested source.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass


class MetaClientNotFound(RuntimeError):
    pass


@dataclass
class MetaResult:
    returncode: int
    stdout: str
    stderr: str


class MetaClient:
    """Wraps the mtkclient META-mode NV record read/write commands."""

    def __init__(self, mtk_bin: str = "mtk"):
        self.mtk_bin = mtk_bin
        if shutil.which(mtk_bin) is None:
            raise MetaClientNotFound(
                "mtkclient 'mtk' entrypoint not found on PATH. "
                "Install it per https://github.com/bkerler/mtkclient."
            )

    def _run(self, *args: str, timeout: float = 60.0) -> MetaResult:
        proc = subprocess.run([self.mtk_bin, *args], capture_output=True, text=True, timeout=timeout)
        return MetaResult(proc.returncode, proc.stdout, proc.stderr)

    def read_imei(self, sim_slot: int) -> MetaResult:
        return self._run("meta", "read-imei", str(sim_slot))

    def restore_imei_from_vault(self, sim_slot: int, imei: str, source: str, gatekeeper) -> MetaResult:
        """`source` must be 'golden_vault' or 'original_factory_marking' (the
        value printed on the unit's own box/SIM-tray/PCB), per Section 2.4.
        gatekeeper is a core.safety.SafetyGatekeeper instance."""
        if not gatekeeper.identifier_operation_allowed(source):
            raise PermissionError(
                f"Identifier restore from source='{source}' is not permitted by the "
                "ethics policy in config/device_profile.yaml."
            )
        return self._run("meta", "write-imei", str(sim_slot), imei)

    def read_wifi_bt_mac(self) -> MetaResult:
        return self._run("meta", "read-nvram-mac")
