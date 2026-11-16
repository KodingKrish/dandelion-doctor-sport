import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

import pytest

from dandelion_doctor.core import crypto
from dandelion_doctor.core.config import load_profile
from dandelion_doctor.core.safety import SafetyGatekeeper
from dandelion_doctor.core.vault import GoldenVaultManager, is_pre_wiped, shannon_entropy

FAKE_PARTITION_DATA = {
    "proinfo": b"PROINFO_BOARD_SERIAL_M2006C3LI_\x01\x02\x03" * 64,
    "nvram": b"NVRAM_RF_CAL_DATA_BLOB_" * 100,
    "nvdata": b"NVDATA_IMEI_MODEM_NV_" * 100,
    "nvcfg": b"NVCFG_CONFIG_" * 50,
    "protect1": b"PROTECT1_MIRROR_" * 50,
    "protect2": b"PROTECT2_MIRROR_" * 50,
    "persist": b"PERSIST_SENSOR_CAL_" * 50,
    "seccfg": b"SECCFG_UNLOCKED_STOCK_" * 20,
    "pgpt": b"PGPT_PRIMARY_GPT_HEADER_" * 30,
}


def fake_dump_fn(name: str) -> bytes:
    return FAKE_PARTITION_DATA.get(name, (name.encode() + b"_PLACEHOLDER_") * 20)


@pytest.fixture
def profile():
    return load_profile()


@pytest.fixture
def vault(profile, tmp_path, monkeypatch):
    # Redirect vault/manifest dirs to a scratch directory so the test never
    # touches the real backups/ tree.
    v = GoldenVaultManager(profile, passphrase="correct horse battery staple")
    v.vault_dir = tmp_path / "golden_nv_vault"
    v.manifests_dir = tmp_path / "manifests"
    v.manifest_path = v.manifests_dir / "golden_vault_manifest.json"
    return v


def test_shannon_entropy_distinguishes_uniform_from_random():
    assert shannon_entropy(b"\x00" * 1000) == 0.0
    assert shannon_entropy(bytes(range(256)) * 10) > 7.5


def test_is_pre_wiped_detects_all_zero_and_all_ff():
    assert is_pre_wiped(b"\x00" * 100) is True
    assert is_pre_wiped(b"\xff" * 100) is True
    assert is_pre_wiped(b"real calibration data") is False


def test_capture_writes_encrypted_blobs_and_manifest(vault):
    required = ["proinfo", "nvram", "nvdata", "nvcfg", "protect1", "protect2", "persist", "seccfg", "pgpt"]
    result = vault.capture(fake_dump_fn, partitions=required)
    assert len(result.entries) == len(required)
    assert result.pre_wiped_partitions == []  # none of the fake data is all-0x00/0xFF

    for name in required:
        enc_path = vault.vault_dir / f"{name}.bin.enc"
        assert enc_path.exists()
        # Ciphertext on disk must not contain the plaintext verbatim.
        assert FAKE_PARTITION_DATA[name][:20] not in enc_path.read_bytes()

    assert vault.manifest_path.exists()


def test_verify_at_rest_passes_after_capture(vault):
    required = ["proinfo", "nvram", "nvdata", "nvcfg", "protect1", "protect2", "persist", "seccfg", "pgpt"]
    vault.capture(fake_dump_fn, partitions=required)
    ok, failures = vault.verify_at_rest(required)
    assert ok
    assert failures == []


def test_verify_at_rest_fails_on_missing_manifest(vault):
    ok, failures = vault.verify_at_rest(["proinfo"])
    assert not ok
    assert "manifest" in failures[0].lower()


def test_verify_at_rest_detects_tampered_blob(vault):
    required = ["proinfo", "nvram"]
    vault.capture(fake_dump_fn, partitions=required)
    # Flip some bytes in the on-disk ciphertext without updating the manifest.
    enc_path = vault.vault_dir / "nvram.bin.enc"
    data = bytearray(enc_path.read_bytes())
    data[-1] ^= 0xFF
    enc_path.write_bytes(bytes(data))

    ok, failures = vault.verify_at_rest(required)
    assert not ok
    assert any("nvram" in f and "mismatch" in f for f in failures)


def test_restore_partition_round_trips_and_matches_manifest(vault):
    vault.capture(fake_dump_fn, partitions=["proinfo"])
    restored = vault.restore_partition("proinfo")
    assert restored == FAKE_PARTITION_DATA["proinfo"]


def test_restore_partition_rejects_wrong_passphrase(vault, profile, tmp_path):
    vault.capture(fake_dump_fn, partitions=["proinfo"])
    wrong = GoldenVaultManager(profile, passphrase="totally the wrong passphrase")
    wrong.vault_dir = vault.vault_dir
    wrong.manifests_dir = vault.manifests_dir
    wrong.manifest_path = vault.manifest_path
    with pytest.raises(crypto.DecryptionError):
        wrong.restore_partition("proinfo")


def test_nv_pre_wipe_detection_flags_blank_partition(vault):
    def blank_dump_fn(name: str) -> bytes:
        return b"\x00" * 4096 if name == "nvram" else fake_dump_fn(name)

    result = vault.capture(blank_dump_fn, partitions=["proinfo", "nvram"])
    assert result.pre_wiped_partitions == ["nvram"]
    assert result.entries[1].nv_pre_wiped is True


def test_safety_gatekeeper_passes_preflight_once_vault_verified(profile, vault, monkeypatch):
    required = profile.safety.golden_vault_partitions
    vault.capture(fake_dump_fn, partitions=required)

    # Disk-space headroom is environment-dependent (CI/sandboxed containers
    # may have little free space); this test is only about the vault check,
    # so relax that unrelated precondition rather than requiring 20 real GB.
    profile.safety.min_free_disk_gb = 0

    gatekeeper = SafetyGatekeeper(profile)

    def fake_status():
        return vault.verify_at_rest(required)

    monkeypatch.setattr(gatekeeper, "golden_vault_status", fake_status)

    from dandelion_doctor.core.safety import DeviceHandshake
    handshake = DeviceHandshake(serialno=profile.unit_lock.fbsn, battery_mv=4000)
    result = gatekeeper.preflight(handshake)
    assert result.ok, result.failures
