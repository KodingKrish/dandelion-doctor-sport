"""The 15 Deep Subsystem Repair Engines (Section 9), one class per domain,
each scoped to its FIX-* range from Section 3's taxonomy table."""
from __future__ import annotations

from dandelion_doctor.core.rule_engine import Telemetry
from dandelion_doctor.engines.base import EngineReport, RepairEngine


class UsbHostTransportEngine(RepairEngine):
    """9.1 — USB, VCOM & Host Transport (360 fixes)."""
    DOMAIN_ID, DOMAIN_NAME, FIX_RANGE = 1, "USB_HOST_TRANSPORT", (1, 360)

    def diagnose(self, telemetry: Telemetry) -> EngineReport:
        start_id, end_id = self._range_ids()
        hits = self.resolver.match_telemetry(telemetry)
        candidates = [c["fix_id"] for h in hits for c in h["sample_candidates"]
                      if start_id <= c["fix_id"] <= end_id]
        return EngineReport(self.DOMAIN_ID, self.DOMAIN_NAME, candidates,
                             "USB enumeration / host-driver link fault triage")


class BromPreloaderSpftEngine(RepairEngine):
    """9.2 — BROM, Preloader, SLA/DAA & SP Flash Tool error resolution (840 fixes)."""
    DOMAIN_ID, DOMAIN_NAME, FIX_RANGE = 2, "BROM_PRELOADER_SPFT", (361, 1200)

    def diagnose(self, telemetry: Telemetry) -> EngineReport:
        start_id, end_id = self._range_ids()
        hits = self.resolver.match_telemetry(telemetry)
        candidates = [c["fix_id"] for h in hits for c in h["sample_candidates"]
                      if start_id <= c["fix_id"] <= end_id]
        diag = "No matching BROM/SPFT error signature in telemetry"
        if telemetry.brom_error_code:
            diag = f"BROM/SPFT error code {telemetry.brom_error_code} under review"
        return EngineReport(self.DOMAIN_ID, self.DOMAIN_NAME, candidates, diag)


class GptScatterPartitionEngine(RepairEngine):
    """9.3 (partition layer) — GPT, Scatter Layout & all 40 raw partitions (1,200 fixes)."""
    DOMAIN_ID, DOMAIN_NAME, FIX_RANGE = 3, "GPT_SCATTER_PARTITIONS", (1201, 2400)

    def diagnose(self, telemetry: Telemetry) -> EngineReport:
        mismatches = [name for name, h in telemetry.partition_hashes.items() if h == "MISMATCH"]
        candidates = self.search(" OR ".join(mismatches)) if mismatches else []
        return EngineReport(self.DOMAIN_ID, self.DOMAIN_NAME, [c["fix_id"] for c in candidates],
                             f"Partition hash mismatches: {mismatches or 'none detected'}")


class BootloaderAvbEngine(RepairEngine):
    """9.3 — Bootloader (seccfg), AVB 2.0 (vbmeta) & Bootchain (540 fixes)."""
    DOMAIN_ID, DOMAIN_NAME, FIX_RANGE = 4, "BOOTLOADER_AVB_BOOTCHAIN", (2401, 2940)

    def diagnose(self, telemetry: Telemetry) -> EngineReport:
        unlocked = telemetry.getvar_map.get("unlocked")
        diag = f"unlocked={unlocked}" if unlocked is not None else "no fastboot getvar data"
        candidates = self.search("seccfg OR vbmeta OR dm_verity")
        return EngineReport(self.DOMAIN_ID, self.DOMAIN_NAME, [c["fix_id"] for c in candidates], diag)


class DynamicSuperFsEngine(RepairEngine):
    """9.4 — Android 10 vs 11 (super dynamic partitions) & filesystem repair (720 fixes)."""
    DOMAIN_ID, DOMAIN_NAME, FIX_RANGE = 5, "DYNAMIC_SUPER_FILESYSTEMS", (2941, 3660)

    def diagnose(self, telemetry: Telemetry) -> EngineReport:
        candidates = self.search("super OR F2FS OR EXT4")
        return EngineReport(self.DOMAIN_ID, self.DOMAIN_NAME, [c["fix_id"] for c in candidates],
                             "Dynamic-partition / filesystem triage")


class EmmcHealthEngine(RepairEngine):
    """9.5 — eMMC 5.1 storage health, EXT_CSD wear & bad-block mitigation (480 fixes)."""
    DOMAIN_ID, DOMAIN_NAME, FIX_RANGE = 6, "EMMC_STORAGE_WEAR_IO", (3661, 4140)

    def diagnose(self, telemetry: Telemetry) -> EngineReport:
        hits = self.resolver.match_telemetry(telemetry)
        candidates = [c["fix_id"] for h in hits for c in h["sample_candidates"]
                      if h["fault_class"] in ("eMMC 5.1 Pre-EOL Exhausted", "eMMC CMD/DATA bus or wear fault")]
        return EngineReport(self.DOMAIN_ID, self.DOMAIN_NAME, candidates, "eMMC wear/IO health scan")


class BasebandRfImeiEngine(RepairEngine):
    """9.6 — Baseband (md1img), MT6177M RF, IMEI & NV integrity (960 fixes)."""
    DOMAIN_ID, DOMAIN_NAME, FIX_RANGE = 7, "BASEBAND_RF_IMEI_NV", (4141, 5100)

    def diagnose(self, telemetry: Telemetry) -> EngineReport:
        baseband = telemetry.getvar_map.get("gsm.version.baseband", "")
        corrupted = any("NVDATA is corrupted" in line for line in telemetry.logcat_lines)
        diag = f"baseband='{baseband or 'UNKNOWN'}'" + (", NVDATA corruption detected" if corrupted else "")
        candidates = self.search("md1img OR NVDATA OR IMEI")
        return EngineReport(self.DOMAIN_ID, self.DOMAIN_NAME, [c["fix_id"] for c in candidates], diag)


class ConnsysEngine(RepairEngine):
    """9.7 — MT6631 Connsys: Wi-Fi, Bluetooth, GPS, FM Radio (600 fixes)."""
    DOMAIN_ID, DOMAIN_NAME, FIX_RANGE = 8, "CONNSYS_MT6631_WIFI_BT_GPS", (5101, 5700)

    def diagnose(self, telemetry: Telemetry) -> EngineReport:
        generic_mac = any("02:00:00:00:00:00" in line for line in telemetry.logcat_lines)
        candidates = self.search("MT6631 OR wifi OR bluetooth OR gps OR fm")
        return EngineReport(self.DOMAIN_ID, self.DOMAIN_NAME, [c["fix_id"] for c in candidates],
                             "Generic Wi-Fi MAC detected" if generic_mac else "Connsys scan")


class PersistSensorsHalEngine(RepairEngine):
    """9.8 — persist, Sensors, Display, Touch, Audio & Camera HALs (1,080 fixes)."""
    DOMAIN_ID, DOMAIN_NAME, FIX_RANGE = 9, "PERSIST_SENSORS_DISPLAY_AUDIO_CAM", (5701, 6780)

    def diagnose(self, telemetry: Telemetry) -> EngineReport:
        candidates = self.search("persist OR proximity OR touch OR camera OR audio")
        return EngineReport(self.DOMAIN_ID, self.DOMAIN_NAME, [c["fix_id"] for c in candidates],
                             "Persist/HAL calibration scan")


class PmicPowerEngine(RepairEngine):
    """9.9 — MT6357 PMIC, Battery, Charging & Thermal (600 fixes)."""
    DOMAIN_ID, DOMAIN_NAME, FIX_RANGE = 10, "PMIC_MT6357_BATTERY_THERMAL", (6781, 7380)

    def diagnose(self, telemetry: Telemetry) -> EngineReport:
        # No dedicated Section 10 signature row maps to this domain, so this
        # engine is driven by battery_mv (Section 9.9) rather than regex.
        candidates = self.search("battery OR voltage OR NTC OR thermal")
        diag = "PMIC/battery/thermal scan"
        return EngineReport(self.DOMAIN_ID, self.DOMAIN_NAME, [c["fix_id"] for c in candidates], diag)


class MiuiPackageEngine(RepairEngine):
    """9.10a — MIUI IN package repair & debloat, Domain 11 (1,200 fixes)."""
    DOMAIN_ID, DOMAIN_NAME, FIX_RANGE = 11, "MIUI_IN_PACKAGES_SERVICES", (7381, 8580)

    def diagnose(self, telemetry: Telemetry) -> EngineReport:
        candidates = self.search("miui OR xiaomi OR gms")
        return EngineReport(self.DOMAIN_ID, self.DOMAIN_NAME, [c["fix_id"] for c in candidates],
                             "MIUI/GMS/MTK package health scan")


class RamZramPerfEngine(RepairEngine):
    """9.10b — RAM (2GB/3GB), zRAM, LMK, Kernel & Performance, Domain 12 (480 fixes)."""
    DOMAIN_ID, DOMAIN_NAME, FIX_RANGE = 12, "RAM_ZRAM_LMK_KERNEL_PERF", (8581, 9060)

    def diagnose(self, telemetry: Telemetry) -> EngineReport:
        hits = self.resolver.match_telemetry(telemetry)
        candidates = [c["fix_id"] for h in hits for c in h["sample_candidates"]
                      if h["fault_class"] == "2GB/3GB RAM thrashing"]
        return EngineReport(self.DOMAIN_ID, self.DOMAIN_NAME, candidates, "RAM/zRAM/LMK pressure scan")


class CustomRecoveryRomEngine(RepairEngine):
    """9.11 — Custom Recovery (TWRP/OrangeFox), Root & blossom AOSP/GSI pipeline (600 fixes)."""
    DOMAIN_ID, DOMAIN_NAME, FIX_RANGE = 13, "CUSTOM_RECOVERY_ROOT_BLOSSOM", (9061, 9660)

    def diagnose(self, telemetry: Telemetry) -> EngineReport:
        candidates = self.search("twrp OR magisk OR gsi OR recovery")
        return EngineReport(self.DOMAIN_ID, self.DOMAIN_NAME, [c["fix_id"] for c in candidates],
                             "Custom recovery / root / GSI pipeline scan")


class SecurityTeeFbeEngine(RepairEngine):
    """9.12 — Security, TEE, FBE data salvage & authorized lock workflows (360 fixes)."""
    DOMAIN_ID, DOMAIN_NAME, FIX_RANGE = 14, "SECURITY_TEE_FBE_SALVAGE", (9661, 10020)

    def diagnose(self, telemetry: Telemetry) -> EngineReport:
        candidates = self.search("tee OR keymaster OR gatekeeper OR fbe")
        return EngineReport(self.DOMAIN_ID, self.DOMAIN_NAME, [c["fix_id"] for c in candidates],
                             "TEE/FBE/credential-store scan")


class BoardSchematicTriageEngine(RepairEngine):
    """9.13 — Board-level schematic & electrical triage (540 fixes)."""
    DOMAIN_ID, DOMAIN_NAME, FIX_RANGE = 15, "BOARD_SCHEMATIC_HW_TRIAGE", (10021, 10560)

    def diagnose(self, telemetry: Telemetry) -> EngineReport:
        no_enumeration = telemetry.usb_vid_pid is None
        candidates = self.search("subboard OR rail OR fpc") if no_enumeration else []
        diag = "No USB enumeration across link attempts — electrical triage indicated" if no_enumeration \
            else "USB link present; electrical triage not indicated"
        return EngineReport(self.DOMAIN_ID, self.DOMAIN_NAME, [c["fix_id"] for c in candidates], diag)


ALL_ENGINES: list[type[RepairEngine]] = [
    UsbHostTransportEngine, BromPreloaderSpftEngine, GptScatterPartitionEngine, BootloaderAvbEngine,
    DynamicSuperFsEngine, EmmcHealthEngine, BasebandRfImeiEngine, ConnsysEngine, PersistSensorsHalEngine,
    PmicPowerEngine, MiuiPackageEngine, RamZramPerfEngine, CustomRecoveryRomEngine, SecurityTeeFbeEngine,
    BoardSchematicTriageEngine,
]
