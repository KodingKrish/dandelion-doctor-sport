"""Phase 0: Forensic Backup & Encrypted Golden Vault (Section 7).

Before ANY partition write or format, dumps every Tier-1 (Identity/NV/Persist)
and Tier-2 (Bootchain) partition, runs an entropy/sanity check to detect a
partition that arrived pre-wiped, and writes an AES-256-GCM encrypted vault
plus a plaintext SHA-256 manifest. This is what SafetyGatekeeper.preflight()
checks for before unlocking any destructive operation.
"""
from __future__ import annotations

import hashlib
import json
import math
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from dandelion_doctor.core import crypto
from dandelion_doctor.core.config import DeviceProfile
from dandelion_doctor.core.scatter import GOLDEN_VAULT_DUMP_SET

DumpFn = Callable[[str], bytes]  # partition_name -> raw bytes, e.g. via BromClient


def shannon_entropy(data: bytes) -> float:
    """Bits of entropy per byte, 0.0 (uniform/constant) to 8.0 (random)."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def non_zero_byte_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return sum(1 for b in data if b != 0x00) / len(data)


def is_pre_wiped(data: bytes) -> bool:
    """Section 7.4: flags NV_PRE_WIPED if a partition is all-0x00 or all-0xFF,
    so a clean template/META restoration workflow is queued instead of
    overwriting with blank backups."""
    if not data:
        return True
    return data.count(data[0]) == len(data) and data[0] in (0x00, 0xFF)


# Section 2.1: these three partitions get the pre-wipe sanity check called
# out explicitly in Section 7.4, though is_pre_wiped() is run on all of them.
NV_PRE_WIPE_WATCHLIST = {"nvram", "nvdata", "persist"}


@dataclass
class PartitionManifestEntry:
    partition: str
    size_bytes: int
    sha256_plaintext: str
    sha256_ciphertext: str
    entropy_bits_per_byte: float
    non_zero_ratio: float
    nv_pre_wiped: bool

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class CaptureResult:
    entries: list[PartitionManifestEntry] = field(default_factory=list)
    pre_wiped_partitions: list[str] = field(default_factory=list)


class GoldenVaultManager:
    def __init__(self, profile: DeviceProfile, passphrase: str):
        self.profile = profile
        self.passphrase = passphrase
        self.vault_dir = profile.resolve_path(profile.paths.golden_vault_dir)
        self.manifests_dir = profile.resolve_path(profile.paths.manifests_dir)
        self.manifest_path = self.manifests_dir / "golden_vault_manifest.json"

    # ---- Section 7.3-7.5: capture ------------------------------------------
    def capture(self, dump_fn: DumpFn, partitions: Optional[list[str]] = None) -> CaptureResult:
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        self.manifests_dir.mkdir(parents=True, exist_ok=True)

        target_partitions = partitions or GOLDEN_VAULT_DUMP_SET
        result = CaptureResult()

        for name in target_partitions:
            raw = dump_fn(name)

            pre_wiped = is_pre_wiped(raw)
            if pre_wiped and name in NV_PRE_WIPE_WATCHLIST:
                result.pre_wiped_partitions.append(name)

            sha256_plaintext = hashlib.sha256(raw).hexdigest()
            blob = crypto.encrypt(raw, self.passphrase, associated_data=name.encode("utf-8"))
            enc_bytes = blob.to_bytes()
            sha256_ciphertext = hashlib.sha256(enc_bytes).hexdigest()

            (self.vault_dir / f"{name}.bin.enc").write_bytes(enc_bytes)

            result.entries.append(PartitionManifestEntry(
                partition=name,
                size_bytes=len(raw),
                sha256_plaintext=sha256_plaintext,
                sha256_ciphertext=sha256_ciphertext,
                entropy_bits_per_byte=round(shannon_entropy(raw), 4),
                non_zero_ratio=round(non_zero_byte_ratio(raw), 4),
                nv_pre_wiped=pre_wiped,
            ))

        self._write_manifest(result)
        return result

    def _write_manifest(self, result: CaptureResult) -> None:
        payload = {
            "target_fbsn": self.profile.unit_lock.fbsn,
            "device": f"{self.profile.device.model} ({self.profile.device.codename})",
            "partitions": {e.partition: e.to_dict() for e in result.entries},
        }
        self.manifest_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    # ---- Section 13.1: at-rest verification (no passphrase required) ------
    def load_manifest(self) -> Optional[dict]:
        if not self.manifest_path.exists():
            return None
        return json.loads(self.manifest_path.read_text(encoding="utf-8"))

    def verify_at_rest(self, required_partitions: list[str]) -> tuple[bool, list[str]]:
        """Checks that every required partition's encrypted blob exists and
        its ciphertext SHA-256 matches the manifest — detects corruption or
        tampering of the backup itself WITHOUT needing the passphrase. This
        is the fast, non-interactive check SafetyGatekeeper runs on every
        preflight."""
        manifest = self.load_manifest()
        if manifest is None:
            return False, ["No golden_vault_manifest.json found"]
        if manifest.get("target_fbsn") != self.profile.unit_lock.fbsn:
            return False, ["Vault manifest FBSN does not match this device profile"]

        failures = []
        entries = manifest.get("partitions", {})
        for name in required_partitions:
            entry = entries.get(name)
            if entry is None:
                failures.append(f"{name}: missing from manifest")
                continue
            enc_path = self.vault_dir / f"{name}.bin.enc"
            if not enc_path.exists():
                failures.append(f"{name}: encrypted blob missing on disk")
                continue
            actual = hashlib.sha256(enc_path.read_bytes()).hexdigest()
            if actual != entry["sha256_ciphertext"]:
                failures.append(f"{name}: ciphertext SHA-256 mismatch (corrupted or tampered)")
        return (not failures), failures

    # ---- Restore path (requires passphrase) --------------------------------
    def restore_partition(self, name: str) -> bytes:
        manifest = self.load_manifest()
        if manifest is None or name not in manifest.get("partitions", {}):
            raise FileNotFoundError(f"{name} not present in Golden Vault manifest")
        enc_path = self.vault_dir / f"{name}.bin.enc"
        blob = crypto.EncryptedBlob.from_bytes(enc_path.read_bytes())
        plaintext = crypto.decrypt(blob, self.passphrase, associated_data=name.encode("utf-8"))

        expected_sha256 = manifest["partitions"][name]["sha256_plaintext"]
        actual_sha256 = hashlib.sha256(plaintext).hexdigest()
        if actual_sha256 != expected_sha256:
            raise crypto.DecryptionError(
                f"{name}: decrypted plaintext SHA-256 does not match manifest "
                "(vault integrity cannot be confirmed)"
            )
        return plaintext
