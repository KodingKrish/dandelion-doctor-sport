"""Complete 40-partition `dandelion` map & repair policies (Section 8)."""
from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum


class SafetyTier(IntEnum):
    TIER_1_GOLDEN_VAULT = 1   # identity/NV/calibration — vault-restore only
    TIER_2_QUARANTINED = 2    # bootchain/co-processor — stock image only, never user-constructed
    TIER_3_STANDARD = 3       # kernel/ramdisk/firmware — reflash from matching stock branch
    TIER_4_PROTECTED = 4      # FRP/user-data/dynamic — never tampered for bypass; safe to wipe for repair


@dataclass(frozen=True)
class PartitionPolicy:
    name: str
    region: str
    tier: SafetyTier
    policy: str


# Parsed from MT6765_Android_scatter.txt + PGPT, covering both
# Android 10 (QCDINXM) and Android 11 (RCDINXM/RCZINXM) variants.
PARTITION_MAP: list[PartitionPolicy] = [
    PartitionPolicy("preloader", "EMMC_BOOT_1", SafetyTier.TIER_2_QUARANTINED,
                     "Never overwrite unless --repair-preloader & dead-boot confirmed"),
    PartitionPolicy("pgpt", "EMMC_USER (Primary GPT)", SafetyTier.TIER_2_QUARANTINED,
                     "Repair from matching scatter/stock GPT if partition boundaries shifted"),
    PartitionPolicy("proinfo", "EMMC_USER", SafetyTier.TIER_1_GOLDEN_VAULT,
                     "Holds board serial/model metadata; vault-restore only"),
    PartitionPolicy("nvram", "EMMC_USER", SafetyTier.TIER_1_GOLDEN_VAULT,
                     "Wi-Fi/BT/RF calibration; vault-restore or META factory repair"),
    PartitionPolicy("nvdata", "EMMC_USER (ext4)", SafetyTier.TIER_1_GOLDEN_VAULT,
                     "Modem IMEI/RF NV; must stay synced with md1img"),
    PartitionPolicy("nvcfg", "EMMC_USER (ext4)", SafetyTier.TIER_1_GOLDEN_VAULT,
                     "NV configuration; repair ext4 or restore from vault"),
    PartitionPolicy("protect1", "EMMC_USER (ext4)", SafetyTier.TIER_1_GOLDEN_VAULT,
                     "Modem protected NV mirror; vault-restore"),
    PartitionPolicy("protect2", "EMMC_USER (ext4)", SafetyTier.TIER_1_GOLDEN_VAULT,
                     "Modem protected NV mirror; vault-restore"),
    PartitionPolicy("persist", "EMMC_USER (ext4)", SafetyTier.TIER_1_GOLDEN_VAULT,
                     "Sensor/camera/display/connsys calibration; e2fsck before re-seed"),
    PartitionPolicy("seccfg", "EMMC_USER", SafetyTier.TIER_1_GOLDEN_VAULT,
                     "Bootloader lock state; always snapshot before unlock/relock"),
    PartitionPolicy("lk", "EMMC_USER", SafetyTier.TIER_2_QUARANTINED, "Little Kernel bootloader; flash from stock TGZ"),
    PartitionPolicy("lk2", "EMMC_USER", SafetyTier.TIER_2_QUARANTINED, "LCD LCM init; flash from stock TGZ"),
    PartitionPolicy("boot", "EMMC_USER", SafetyTier.TIER_3_STANDARD, "Kernel/ramdisk; stock or verified custom"),
    PartitionPolicy("recovery", "EMMC_USER", SafetyTier.TIER_3_STANDARD, "Stock Mi Recovery / TWRP / OrangeFox"),
    PartitionPolicy("dtbo", "EMMC_USER", SafetyTier.TIER_3_STANDARD, "Device Tree Overlays; must match dandelion"),
    PartitionPolicy("vbmeta", "EMMC_USER", SafetyTier.TIER_3_STANDARD, "AVB 2.0 root digest; stock or --disable-verity"),
    PartitionPolicy("vbmeta_system", "EMMC_USER", SafetyTier.TIER_3_STANDARD, "AVB 2.0 system digest"),
    PartitionPolicy("vbmeta_vendor", "EMMC_USER", SafetyTier.TIER_3_STANDARD, "AVB 2.0 vendor digest"),
    PartitionPolicy("tee1", "EMMC_USER", SafetyTier.TIER_2_QUARANTINED, "TrustZone OS; flash stock pair if TEE fails"),
    PartitionPolicy("tee2", "EMMC_USER", SafetyTier.TIER_2_QUARANTINED, "TrustZone OS; flash stock pair if TEE fails"),
    PartitionPolicy("scp1", "EMMC_USER", SafetyTier.TIER_2_QUARANTINED, "System Companion Processor; stock TGZ"),
    PartitionPolicy("scp2", "EMMC_USER", SafetyTier.TIER_2_QUARANTINED, "System Companion Processor; stock TGZ"),
    PartitionPolicy("sspm_1", "EMMC_USER", SafetyTier.TIER_2_QUARANTINED, "Secure System Power Manager; stock TGZ"),
    PartitionPolicy("sspm_2", "EMMC_USER", SafetyTier.TIER_2_QUARANTINED, "Secure System Power Manager; stock TGZ"),
    PartitionPolicy("md1img", "EMMC_USER", SafetyTier.TIER_3_STANDARD, "LTE/WCDMA/GSM modem firmware; must match vendor"),
    PartitionPolicy("spmfw", "EMMC_USER", SafetyTier.TIER_2_QUARANTINED, "Sleep Power Manager firmware; stock TGZ"),
    PartitionPolicy("mcupmfw", "EMMC_USER", SafetyTier.TIER_2_QUARANTINED, "MCU firmware; stock TGZ"),
    PartitionPolicy("odmdtbo", "EMMC_USER", SafetyTier.TIER_3_STANDARD, "ODM DTBO where present; stock TGZ"),
    PartitionPolicy("logo", "EMMC_USER", SafetyTier.TIER_3_STANDARD, "Boot splash/charging graphics; stock TGZ"),
    PartitionPolicy("frp", "EMMC_USER", SafetyTier.TIER_4_PROTECTED, "Google FRP store; never tampered for bypass"),
    PartitionPolicy("para", "EMMC_USER", SafetyTier.TIER_4_PROTECTED, "Boot-reason BCB flag; safe to zero to exit loops"),
    PartitionPolicy("misc", "EMMC_USER", SafetyTier.TIER_4_PROTECTED, "Boot-reason BCB flag; safe to zero to exit loops"),
    PartitionPolicy("expdb", "EMMC_USER", SafetyTier.TIER_4_PROTECTED, "Crash dumps"),
    PartitionPolicy("boot_para", "EMMC_USER", SafetyTier.TIER_4_PROTECTED, "Boot parameters"),
    PartitionPolicy("super", "EMMC_USER (Android 11+)", SafetyTier.TIER_4_PROTECTED,
                     "Dynamic LP container holding system/vendor/product/odm"),
    PartitionPolicy("system", "EMMC_USER (Android 10)", SafetyTier.TIER_4_PROTECTED, "Static partition on QCDINXM"),
    PartitionPolicy("vendor", "EMMC_USER (Android 10)", SafetyTier.TIER_4_PROTECTED, "Static partition on QCDINXM"),
    PartitionPolicy("cache", "EMMC_USER", SafetyTier.TIER_4_PROTECTED, "Recovery staging; wipe cleanly on major OS change"),
    PartitionPolicy("metadata", "EMMC_USER", SafetyTier.TIER_4_PROTECTED, "FBE metadata; wipe cleanly on major OS change"),
    PartitionPolicy("userdata", "EMMC_USER", SafetyTier.TIER_4_PROTECTED, "F2FS/EXT4 encrypted user storage"),
    PartitionPolicy("sgpt", "EMMC_USER", SafetyTier.TIER_2_QUARANTINED, "Backup GPT header"),
]

PARTITIONS_BY_NAME: dict[str, PartitionPolicy] = {p.name: p for p in PARTITION_MAP}

# Phase 0 Tier-1/Tier-2 forensic backup set (Section 7.3)
GOLDEN_VAULT_DUMP_SET = [
    "proinfo", "nvram", "nvdata", "nvcfg", "protect1", "protect2", "persist", "seccfg",
    "preloader", "pgpt", "sgpt", "lk", "lk2", "tee1", "tee2", "scp1", "scp2",
    "sspm_1", "sspm_2", "spmfw", "mcupmfw", "md1img", "dtbo", "vbmeta",
    "vbmeta_system", "vbmeta_vendor", "boot", "recovery",
]


def is_destructive_without_vault(partition_name: str) -> bool:
    policy = PARTITIONS_BY_NAME.get(partition_name)
    return policy is not None and policy.tier in (SafetyTier.TIER_1_GOLDEN_VAULT, SafetyTier.TIER_2_QUARANTINED)
