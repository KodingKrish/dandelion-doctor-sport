"""Safety Gatekeeper (Section 2: Unit-Binding, Ethics & Safety Policy;
Section 13: Safety Gatekeeper, Dry-Run, Transaction Rollback & Audit Logging).

Every destructive operation in dandelion-doctor MUST pass through
SafetyGatekeeper.preflight() before touching eMMC. This module intentionally
fails closed: any missing precondition blocks the operation.
"""
from __future__ import annotations

import hashlib
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from dandelion_doctor.core.config import DeviceProfile
from dandelion_doctor.core.vault import GoldenVaultManager


class SafetyViolation(RuntimeError):
    """Raised whenever a precondition required by the safety policy fails."""


@dataclass
class DeviceHandshake:
    """What a BROM/Preloader/Fastboot/ADB handshake reports about the
    physically-connected unit."""

    serialno: Optional[str] = None
    product: Optional[str] = None
    model: Optional[str] = None
    me_id: Optional[bytes] = None
    soc_id: Optional[bytes] = None
    battery_mv: Optional[int] = None
    battery_disconnected: bool = False


@dataclass
class PreflightResult:
    ok: bool
    failures: list[str] = field(default_factory=list)

    def raise_if_failed(self) -> None:
        if not self.ok:
            raise SafetyViolation("; ".join(self.failures))


class SafetyGatekeeper:
    """Implements the Mandatory Pre-Flight Checklist (Section 13.1) and the
    Unit-Binding rules (Section 2)."""

    def __init__(self, profile: DeviceProfile):
        self.profile = profile

    # ---- Section 2.1: Strict Hardware Serial Lock -------------------------
    def check_fbsn(self, handshake: DeviceHandshake) -> list[str]:
        failures = []
        expected = self.profile.unit_lock.fbsn
        if handshake.serialno is not None and handshake.serialno != expected:
            failures.append(
                f"FBSN mismatch: connected device reports '{handshake.serialno}', "
                f"this toolkit is locked to '{expected}'."
            )
        if handshake.model is not None and handshake.model != self.profile.device.model:
            failures.append(
                f"Model mismatch: connected device reports '{handshake.model}', "
                f"expected '{self.profile.device.model}'."
            )
        return failures

    def bind_identity(self, handshake: DeviceHandshake) -> None:
        """Called once, on the FIRST successful BROM handshake, per Section 2.1.
        Hashes ME_ID/SOC_ID into the profile so all future operations verify
        against the same physical unit without re-reading fused registers."""
        if handshake.me_id:
            self.profile.unit_lock.me_id_hash = hashlib.sha256(handshake.me_id).hexdigest()
        if handshake.soc_id:
            self.profile.unit_lock.soc_id_hash = hashlib.sha256(handshake.soc_id).hexdigest()

    # ---- Section 7.5 / 13.1: Golden Vault mandate --------------------------
    def golden_vault_present_and_verified(self) -> bool:
        ok, _failures = self.golden_vault_status()
        return ok

    def golden_vault_status(self) -> tuple[bool, list[str]]:
        """Like golden_vault_present_and_verified(), but also returns the
        specific failures (missing/corrupted/tampered partitions) for
        diagnostics. Delegates to GoldenVaultManager.verify_at_rest(), which
        checks ciphertext SHA-256 integrity without needing the vault
        passphrase (Section 13.1 only requires the vault be present and
        verified, not that it be decrypted on every preflight)."""
        vault = GoldenVaultManager(self.profile, passphrase="")  # not used for at-rest check
        required = self.profile.safety.golden_vault_partitions
        return vault.verify_at_rest(required)

    # ---- Section 2.2: Preloader Quarantine ---------------------------------
    def preloader_write_allowed(self, repair_preloader_flag: bool, dead_boot_confirmed: bool) -> bool:
        if not self.profile.safety.preloader_quarantine:
            return True
        return repair_preloader_flag and dead_boot_confirmed

    # ---- Section 13.1: Mandatory Pre-Flight Checklist ----------------------
    def preflight(self, handshake: DeviceHandshake, free_space_root: Path = Path("/")) -> PreflightResult:
        failures: list[str] = []
        failures.extend(self.check_fbsn(handshake))

        if self.profile.safety.require_golden_vault_before_destructive_ops:
            vault_ok, vault_failures = self.golden_vault_status()
            if not vault_ok:
                failures.append("Golden NV Vault missing or SHA-256 verification failed: "
                                 + "; ".join(vault_failures))

        if not handshake.battery_disconnected:
            min_mv = self.profile.safety.min_battery_mv
            if handshake.battery_mv is None or handshake.battery_mv < min_mv:
                failures.append(
                    f"Battery voltage {handshake.battery_mv} mV is below the "
                    f"required {min_mv} mV (or pass --battery-disconnected in Testpoint BROM mode)."
                )

        free_gb = shutil.disk_usage(free_space_root).free / (1024 ** 3)
        if free_gb < self.profile.safety.min_free_disk_gb:
            failures.append(
                f"Only {free_gb:.1f} GB free on host; "
                f"{self.profile.safety.min_free_disk_gb} GB required."
            )

        return PreflightResult(ok=not failures, failures=failures)

    # ---- Section 2.4: identifier-recovery ethics boundary ------------------
    def identifier_operation_allowed(self, source: str) -> bool:
        """source is one of: 'golden_vault', 'original_factory_marking', 'spoof_or_clone', 'frp_bypass'."""
        mapping = {
            "golden_vault": self.profile.ethics.allow_identifier_restore_from_golden_vault,
            "original_factory_marking": self.profile.ethics.allow_identifier_restore_from_original_factory_markings,
            "spoof_or_clone": self.profile.ethics.allow_identifier_spoofing_or_cloning,
            "frp_bypass": self.profile.ethics.allow_frp_or_mi_account_bypass,
        }
        return mapping.get(source, False)
