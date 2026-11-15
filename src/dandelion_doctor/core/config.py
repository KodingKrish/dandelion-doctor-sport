"""Loads and validates config/device_profile.yaml (Section 2: Unit-Binding)."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, Field

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_PROFILE_PATH = REPO_ROOT / "config" / "device_profile.yaml"


class DeviceSpec(BaseModel):
    model: str
    marketing_name: str
    codename: str
    tree_family: str
    chipset: str
    brom_hw_code: str
    brom_hw_subcode: str
    brom_hw_ver: str
    pmic: str
    rf_transceiver: str
    connsys: str
    storage: str
    ram_variants: list[str]
    stock_branches: list[str]


class UnitLock(BaseModel):
    fbsn: str
    me_id_hash: Optional[str] = None
    soc_id_hash: Optional[str] = None


class SafetyPolicy(BaseModel):
    preloader_quarantine: bool = True
    require_golden_vault_before_destructive_ops: bool = True
    min_battery_mv: int = 3650
    min_free_disk_gb: int = 20
    golden_vault_partitions: list[str] = Field(default_factory=list)


class EthicsPolicy(BaseModel):
    allow_identifier_restore_from_golden_vault: bool = True
    allow_identifier_restore_from_original_factory_markings: bool = True
    allow_identifier_spoofing_or_cloning: bool = False
    allow_frp_or_mi_account_bypass: bool = False


class Paths(BaseModel):
    catalog_jsonl: str
    catalog_db: str
    golden_vault_dir: str
    snapshots_dir: str
    manifests_dir: str
    logs_dir: str


class DeviceProfile(BaseModel):
    device: DeviceSpec
    unit_lock: UnitLock
    safety: SafetyPolicy
    ethics: EthicsPolicy
    paths: Paths

    def resolve_path(self, relative: str) -> Path:
        return REPO_ROOT / relative


def load_profile(path: Path = DEFAULT_PROFILE_PATH) -> DeviceProfile:
    with open(path, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)
    return DeviceProfile.model_validate(raw)
