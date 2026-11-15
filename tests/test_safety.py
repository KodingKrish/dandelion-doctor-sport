import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

import pytest

from dandelion_doctor.core.config import load_profile
from dandelion_doctor.core.safety import DeviceHandshake, SafetyGatekeeper, SafetyViolation


@pytest.fixture
def profile():
    return load_profile()


@pytest.fixture
def gatekeeper(profile):
    return SafetyGatekeeper(profile)


def test_blocks_on_wrong_fbsn(gatekeeper):
    handshake = DeviceHandshake(serialno="WRONGSERIALNUMBERxx", battery_mv=4000)
    result = gatekeeper.preflight(handshake)
    assert not result.ok
    assert any("FBSN mismatch" in f for f in result.failures)


def test_accepts_correct_fbsn_but_still_blocks_without_vault(gatekeeper, profile):
    handshake = DeviceHandshake(serialno=profile.unit_lock.fbsn, battery_mv=4000)
    result = gatekeeper.preflight(handshake)
    # No Golden Vault has been captured in this fresh checkout, so it must fail closed.
    assert not result.ok
    assert any("Golden NV Vault" in f for f in result.failures)


def test_blocks_on_low_battery(gatekeeper, profile):
    handshake = DeviceHandshake(serialno=profile.unit_lock.fbsn, battery_mv=3000)
    result = gatekeeper.preflight(handshake)
    assert not result.ok
    assert any("Battery voltage" in f for f in result.failures)


def test_battery_disconnected_flag_bypasses_voltage_check(gatekeeper, profile):
    handshake = DeviceHandshake(serialno=profile.unit_lock.fbsn, battery_disconnected=True)
    result = gatekeeper.preflight(handshake)
    assert not any("Battery voltage" in f for f in result.failures)


def test_preloader_quarantined_by_default(gatekeeper):
    assert gatekeeper.preloader_write_allowed(repair_preloader_flag=False, dead_boot_confirmed=True) is False
    assert gatekeeper.preloader_write_allowed(repair_preloader_flag=True, dead_boot_confirmed=False) is False
    assert gatekeeper.preloader_write_allowed(repair_preloader_flag=True, dead_boot_confirmed=True) is True


def test_identifier_spoofing_and_frp_bypass_disallowed(gatekeeper):
    assert gatekeeper.identifier_operation_allowed("golden_vault") is True
    assert gatekeeper.identifier_operation_allowed("original_factory_marking") is True
    assert gatekeeper.identifier_operation_allowed("spoof_or_clone") is False
    assert gatekeeper.identifier_operation_allowed("frp_bypass") is False


def test_raise_if_failed_raises_safety_violation(gatekeeper):
    handshake = DeviceHandshake(serialno="WRONG", battery_mv=4000)
    result = gatekeeper.preflight(handshake)
    with pytest.raises(SafetyViolation):
        result.raise_if_failed()
