#!/usr/bin/env python3
"""
Deterministic 10,560-Fix Catalog Compiler for Redmi 9A Sport (M2006C3LI / dandelion)
Target FBSN: 6XLFMR9DVK7PCM6H
"""
from __future__ import annotations
import json
import sqlite3
from itertools import product
from pathlib import Path

TARGET_FBSN = "6XLFMR9DVK7PCM6H"
OUT_DIR = Path(__file__).resolve().parent.parent / "assets" / "catalog"

PARTITIONS_40 = [
    "preloader", "pgpt", "proinfo", "nvram", "nvdata", "nvcfg", "protect1", "protect2",
    "persist", "seccfg", "lk", "lk2", "boot", "recovery", "dtbo", "vbmeta",
    "vbmeta_system", "vbmeta_vendor", "tee1", "tee2", "scp1", "scp2", "sspm_1", "sspm_2",
    "md1img", "spmfw", "mcupmfw", "odmdtbo", "logo", "frp", "para", "misc",
    "expdb", "boot_para", "super", "system", "vendor", "cache", "metadata", "userdata"
]

SPFT_BROM_CODES_42 = [
    "1002", "1003", "1011", "1012", "1013", "1018", "1040", "1041", "1042",
    "2004", "2005", "2020", "2035", "3001", "3012", "3013", "3054", "3066",
    "3140", "3149", "3168", "3178", "3182", "4001", "4008", "4009", "4010",
    "4032", "4037", "4050", "4058", "5000", "5002", "5007", "5054", "5066",
    "5069", "6010", "6012", "6045", "8038", "0xC003001D"
]

MIUI_PACKAGES_120 = [
    "com.miui.msa.global", "com.miui.analytics", "com.xiaomi.joyose", "com.miui.daemon",
    "com.miui.bugreport", "com.miui.miservice", "com.miui.yellowpage", "com.miui.hybrid",
    "com.miui.hybrid.accessory", "com.miui.player", "com.miui.videoplayer", "com.miui.weather2",
    "com.miui.notes", "com.miui.compass", "com.miui.calculator", "com.miui.screenrecorder",
    "com.miui.cleanmaster", "com.miui.securitycenter", "com.miui.securityadd", "com.miui.guardprovider",
    "com.miui.powerkeeper", "com.miui.cloudservice", "com.miui.cloudbackup", "com.miui.micloudsync",
    "com.xiaomi.mipicks", "com.xiaomi.payment", "com.xiaomi.midrop", "com.xiaomi.scanner",
    "com.xiaomi.glgm", "com.xiaomi.discover", "com.xiaomi.xmsf", "com.xiaomi.account",
    "com.xiaomi.finddevice", "com.xiaomi.simactivate.service", "com.miui.home", "com.android.systemui",
    "com.android.settings", "com.android.phone", "com.android.mms", "com.android.contacts",
    "com.android.providers.telephony", "com.android.providers.media", "com.android.providers.downloads",
    "com.android.providers.contacts", "com.android.vending", "com.google.android.gms",
    "com.google.android.gsf", "com.google.android.webview", "com.google.android.youtube",
    "com.google.android.apps.maps", "com.google.android.gm", "com.google.android.apps.photos",
    "com.google.android.apps.docs", "com.google.android.videos", "com.google.android.music",
    "com.google.android.tts", "com.google.android.marvin.talkback", "com.google.android.inputmethod.latin",
    "com.google.android.setupwizard", "com.google.android.partnersetup", "com.google.android.feedback",
    "com.google.android.printservice.recommendation", "com.google.android.syncadapters.contacts",
    "com.google.android.syncadapters.calendar", "com.google.android.ext.services",
    "com.google.android.permissioncontroller", "com.google.android.packageinstaller",
    "com.mediatek.ims", "com.mediatek.wfo.impl", "com.mediatek.telephony", "com.mediatek.engineermode",
    "com.mediatek.batterywarning", "com.mediatek.thermalmanager", "com.mediatek.mtklogger",
    "com.mediatek.atci.service", "com.mediatek.connectivity", "com.mediatek.omacp",
    "com.mediatek.lbs.em2.ui", "com.mediatek.voicecommand", "com.mediatek.gnssdebugreport",
    "com.miui.wmsvc", "com.miui.vsimcore", "com.miui.touchassistant", "com.miui.translation.kingsoft",
    "com.miui.translation.youdao", "com.miui.fm", "com.miui.fmservice", "com.miui.gallery",
    "com.miui.backup", "com.miui.aod", "com.miui.face", "com.miui.extraphoto",
    "com.miui.cit", "com.miui.android.fashiongallery", "com.miui.global.packageinstaller",
    "com.miui.notification", "com.miui.core", "com.miui.rom", "com.miui.system",
    "com.miui.sysopt", "com.miui.freeform", "com.miui.audiomonitor", "com.miui.misound",
    "com.xiaomi.barrage", "com.xiaomi.bluetooth", "com.xiaomi.cameratools", "com.xiaomi.location.fused",
    "com.xiaomi.metoknlp", "com.xiaomi.mi_connect_service", "com.xiaomi.mirror", "com.xiaomi.mircs",
    "com.xiaomi.otrpbroker", "com.xiaomi.providers.appindex", "com.xiaomi.upnp", "com.xiaomi.xmsfkeeper",
    "com.facebook.appmanager", "com.facebook.services", "com.facebook.system",
    "com.android.bluetooth", "com.android.nfc"
]

DOMAIN_SPECS = [
    (1, "USB_HOST_TRANSPORT", "HOST_USB",
     ["Win_UsbDk", "Win_WinUSB", "Win_MTK_VCOM", "Linux_udev", "Linux_MM_Ignore", "macOS_libusb"],
     ["0E8D:0003_BROM", "0E8D:2000_Preloader", "0E8D:2001_DA", "0E8D:2007_META", "18D1:D00D_Fastboot",
      "2717:FF08_FastbootMI", "2717:FF48_ADB", "2717:FF18_Sideload", "Dead_PHY", "Brownout_Loop"],
     ["Descriptor_Stall", "Bulk_Timeout", "Permission_Denied", "Endpoint_Halt", "Cable_IR_Drop", "xHCI_Power_Throttle"]),
    (2, "BROM_PRELOADER_SPFT", "BROM",
     SPFT_BROM_CODES_42,
     ["2GB_Micron", "2GB_SamsungHynix", "3GB_Micron", "3GB_SamsungHynix"],
     ["Dead_Boot", "Preloader_Loop", "BROM_Latched", "Patched_SecBoot", "Testpoint_Entry"]),
    (3, "GPT_SCATTER_PARTITIONS", "BROM_OR_FASTBOOT",
     PARTITIONS_40,
     ["SHA256_Mismatch", "Zeroed_Header", "Truncated_Write", "CrossDevice_Image", "Bad_Offset", "Corrupt_Sparse"],
     ["BROM_Readback_Repair", "GoldenVault_Restore", "StockTGZ_Flash", "Fastboot_Flash", "Fastbootd_Remap"]),
    (4, "BOOTLOADER_AVB_BOOTCHAIN", "BROM_OR_FASTBOOT",
     ["seccfg_Locked_Corrupt", "seccfg_Unlocked_Stock", "dm_verity_Yellow", "dm_verity_Red",
      "System_Destroyed", "Orange_State_Hang", "ARB_Anti_Mismatch", "vbmeta_Digest_Fail", "lk_BCB_Stuck"],
     ["V12.0.10.QCDINXM", "V12.0.15.QCDINXM", "V12.0.20.QCDINXM", "V12.0.26.QCDINXM",
      "V12.5.4.RCDINXM", "V12.5.9.RCDINXM", "V12.5.12.RCDINXM", "V12.5.14.RCZINXM", "V12.5.16.RCZINXM", "V12.5.18.RCZINXM"],
     ["AVB_Disable_Flags", "seccfg_Vault_Restore", "Stock_Resign", "lk_Reflash", "misc_BCB_Clear", "Official_Unlock_Check"]),
    (5, "DYNAMIC_SUPER_FILESYSTEMS", "FASTBOOTD_OR_RECOVERY",
     ["super", "system", "vendor", "product", "odm", "system_ext", "userdata", "metadata", "cache", "persist", "nvdata", "nvcfg"],
     ["LP_Metadata_Corrupt", "Insufficient_Super_Space", "Fastbootd_Stall", "F2FS_Superblock_Corrupt",
      "EXT4_Orphan_Loop", "FBE_Keymaster_Mismatch", "Quota_Overflow", "ReadOnly_Remount", "Bad_Cluster", "Sparse_Overflow"],
     ["lpmake_Rebuild", "lpunpack_Extract", "fsck_f2fs_Repair", "e2fsck_Repair", "mke2fs_Format", "fastbootd_Resize"]),
    (6, "EMMC_STORAGE_WEAR_IO", "ADB_OR_BROM",
     ["PreEOL_0x02_Warn", "PreEOL_0x03_EOL", "WearA_0x08", "WearA_0x0A", "WearB_0x08", "WearB_0x0A",
      "MMC0_Timeout", "CRC_Data_Error", "CMD18_Read_Fail", "CMD25_Write_Fail", "WP_Latch", "RPMB_Auth_Err",
      "Discard_Trim_Hang", "Queue_Depth_Stall", "Phantom_Write_Revert", "EXT4_Journal_Abort"],
     ["EMMC_Boot1", "EMMC_Boot2", "EMMC_RPMB", "User_GPT", "OS_Region", "Data_Region"],
     ["IO_Scheduler_Tune", "Safe_Fstrim", "ReadOnly_Verify", "BadBlock_Bypass_Format", "BGA_EOL_Escalate"]),
    (7, "BASEBAND_RF_IMEI_NV", "BROM_OR_META",
     ["Unknown_Baseband", "Invalid_IMEI_1", "Invalid_IMEI_2", "NVDATA_Corrupted", "NVRAM_Err_0x10",
      "VoLTE_IMS_Fail", "LTE_B40_B41_Drop", "WCDMA_GSM_Fallback", "SIM1_Detect_Fail", "SIM2_Detect_Fail",
      "SAR_Sensor_Fail", "RF_Cal_Checksum", "md1img_Mismatch", "protect1_Corrupt", "protect2_Corrupt", "proinfo_Mismatch"],
     ["Vault_Intact_Q", "Vault_Intact_R", "Vault_Missing_META_Q", "Vault_Missing_META_R",
      "Modem_CrossBranch", "SIM_Slot1", "SIM_Slot2", "Jio_VoLTE_IN", "Airtel_VoLTE_IN", "Vi_BSNL_IN"],
     ["Golden_NV_Restore", "md1img_Branch_Sync", "META_Original_IMEI", "AT_EGMR_Verify", "nvcfg_Reset", "RF_Coax_Triage"]),
    (8, "CONNSYS_MT6631_WIFI_BT_GPS", "ADB_OR_BROM",
     ["WiFi_MAC_0200", "WiFi_Toggle_Dead", "Ch12_13_IN_Fail", "WiFi_Sleep_Drop", "WiFi_Auth_Loop",
      "BT_Service_Crash", "BT_A2DP_Stutter", "BT_SCO_Call_Dead", "BT_MAC_Generic", "Connsys_FW_Mismatch",
      "GPS_Zero_Sats", "AGPS_SUPL_Fail", "GLONASS_BDS_Slow", "FM_Tuner_Dead", "FM_Antenna_Fail",
      "Hotspot_DHCP_Fail", "WiFi_Direct_Fail", "RSSI_Attenuation", "WCN_Watchdog_Reset", "NVRAM_WiFi_CRC"],
     ["nvram_Offset", "persist_Connsys", "vendor_FW_221129", "Framework_SettingsDB", "Netstack_Reset", "MT6631_HW_Triage"],
     ["Vault_Restore", "Connsys_Patch_Sync", "Net_Reset", "CountryCode_IN", "Antenna_Check"]),
    (9, "PERSIST_SENSORS_DISPLAY_AUDIO_CAM", "ADB_OR_BROM",
     ["Proximity", "Accelerometer", "Ambient_Light", "Virtual_Gyro", "LCD_Backlight", "LCD_LCM_Panel",
      "Touch_Digitizer", "DT2W", "Rear_Cam_13MP", "Front_Cam_5MP", "Flash_LED", "Earpiece",
      "Loudspeaker", "Primary_Mic", "Secondary_Mic", "Jack_mt6357_accdet", "Vibrator", "HW_Keys"],
     ["Kernel_Probe_Fail", "Persist_Cal_Missing", "I2C_NACK", "DTBO_Mismatch", "HAL_Crash",
      "SELinux_Denial", "Stuck_Reading", "Audio_Headset_Stuck", "Black_Viewfinder", "PDAF_Hunt", "Dim_Backlight", "Touch_DeadZone"],
     ["Persist_e2fsck", "Stock_Persist_Reseed", "DTBO_LK_Sync", "HAL_Cache_Clear", "FPC_HW_Triage"]),
    (10, "PMIC_MT6357_BATTERY_THERMAL", "ALL_MODES",
     ["Stuck_0_Percent", "Stuck_1_Percent", "Stuck_50_Percent", "Voltage_Below_3400mV", "USB_450mA_SDP_Cap",
      "Charge_Logo_Loop", "NTC_Minus40C", "NTC_Plus80C", "Shutdown_At_20Pct", "MT6357_Reset_Loop",
      "CPU_Throttle_800MHz", "DeepSleep_Wakelock", "OTG_5V_Fail", "FuelGauge_Drift", "USB_Overvoltage"],
     ["BROM", "Preloader", "Fastboot", "Offline_Charge", "OS_Idle", "OS_Load", "Battery_Unplugged", "Ext_5V_2A"],
     ["Precharge_Wait", "Gauge_Reset", "Thermal_Config_Restore", "USB_Port_Check", "PMIC_IC_Escalate"]),
    (11, "MIUI_IN_PACKAGES_SERVICES", "ADB_OS",
     MIUI_PACKAGES_120,
     ["OOM_Crash", "Wakelock_Spin", "Telemetry_Drain", "PackageDB_Corrupt", "Boot_ANR_Loop"],
     ["Safe_User0_Disable_Or_Restore", "Clear_And_Dexopt_SpeedProfile"]),
    (12, "RAM_ZRAM_LMK_KERNEL_PERF", "ADB_OS_OR_ROOT",
     ["OOM_Thrash", "zRAM_Size", "zRAM_Algorithm", "VM_Swappiness", "VFS_Cache_Pressure", "LMK_PSI_Minfree",
      "PowerVR_Backpressure", "CPU_Governor", "Dex2oat_Profile", "Binder_Pressure", "BG_App_Kill",
      "Launcher_Redraw", "WebView_MemSpike", "UI_Jank_60Hz", "Input_Latency", "IO_Readahead"],
     ["2GB_MIUI12", "2GB_MIUI12_5", "2GB_AOSP", "3GB_MIUI12", "3GB_MIUI12_5", "3GB_AOSP"],
     ["Conservative", "Balanced", "Aggressive_2GB", "LowLatency", "Stock_Default"]),
    (13, "CUSTOM_RECOVERY_ROOT_BLOSSOM", "FASTBOOT_OR_RECOVERY",
     ["TWRP_Touch_Dead", "Recovery_FBE_Fail", "Magisk_Bootloop", "Play_Integrity_Fail", "Zygisk_Crash",
      "GSI_Super_Oversize", "GSI_VNDK_Bootloop", "AOSP_RILD_Crash", "GSI_VoLTE_Missing", "TWRP_Charge_Bug",
      "OFOX_Mount_Fail", "KernelSU_Mismatch", "DT2W_AOSP_Broken", "BT_Audio_GSI_Fail", "Offline_Alarm_Fail"],
     ["Q_Vendor_TWRP", "Q_Vendor_OFOX", "R_Vendor_TWRP", "R_Vendor_OFOX", "R_Vendor_LOS", "R_Vendor_crDroid", "R_Vendor_GSI", "Stock_Restore"],
     ["Patch_Boot", "Flash_VBMeta_NoVerity", "Resize_Super", "Apply_Overlay", "Revert_Stock"]),
    (14, "SECURITY_TEE_FBE_SALVAGE", "ADB_RECOVERY_OR_BROM",
     ["TEE1_TEE2_Fail", "Keymaster_Crypto_Err", "Gatekeeper_PIN_Bug", "SELinux_AVC_Loop", "FBE_Media_Salvage",
      "Auth_MiAccount_Signout", "Auth_FRP_Hygienic_Reset", "Play_Protect_Uncert", "Attestation_Key_Check",
      "Locksettings_DB_Corrupt", "Credential_Storage_Reset", "VerifiedBoot_Key_Check"],
     ["BROM", "FASTBOOT", "FASTBOOTD", "ADB_OS", "ADB_RECOVERY", "SIDELOAD"],
     ["TEE_Pair_Flash", "Authorized_Salvage", "SELinux_Context_Restore", "Crypto_Metadata_Wipe", "Owner_Portal_Guide"]),
    (15, "BOARD_SCHEMATIC_HW_TRIAGE", "PHYSICAL_MULTIMETER",
     ["USB_Subboard", "Main_Sub_FPC", "Battery_FPC_NTC", "MT6357_Rails", "Charger_IC_Path",
      "Backlight_Boost", "LCD_FPC", "Touch_FPC", "Rear_Cam_FPC", "Front_Cam_FPC",
      "Audio_Jack", "Buzzer_Earpiece", "Mic_Path", "RF_Coax_MT6177M", "WCN_MT6631_Path",
      "eMMC_BGA221_Bus", "BROM_Testpoint_CLK_KCOL0", "Vol_Power_Flex"],
     ["Open_Line_OL", "Short_To_GND", "Voltage_Rail_Sag", "Intermittent_Flex", "Liquid_Corrosion", "Thermal_Hotspot"],
     ["Visual_Inspect", "Diode_Mode_Check", "Rail_Voltage_Probe", "Reseat_Clean_IPA", "Component_Swap"])
]


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    jsonl_path = OUT_DIR / "fixes_10560.jsonl"
    db_path = OUT_DIR / "fixes_10560.db"
    if db_path.exists():
        db_path.unlink()

    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE fixes (fix_id TEXT PRIMARY KEY, domain_id INTEGER, domain_name TEXT, "
        "transport TEXT, key1 TEXT, key2 TEXT, key3 TEXT, title TEXT, payload_json TEXT)"
    )
    conn.execute("CREATE VIRTUAL TABLE fixes_fts USING fts5(fix_id, title, payload_json)")

    counter = 0
    with jsonl_path.open("w", encoding="utf-8") as fh:
        for domain_id, domain_name, transport, dim1, dim2, dim3 in DOMAIN_SPECS:
            for k1, k2, k3 in product(dim1, dim2, dim3):
                counter += 1
                fix_id = f"FIX-{counter:05d}"
                record = {
                    "fix_id": fix_id,
                    "target_fbsn": TARGET_FBSN,
                    "device": "M2006C3LI (dandelion)",
                    "domain_id": domain_id,
                    "domain_name": domain_name,
                    "transport": transport,
                    "fault_vector": k1,
                    "context": k2,
                    "remediation": k3,
                    "title": f"[{domain_name}] Fix {k1} under {k2} via {k3}",
                    "requires_golden_vault": domain_id in {2, 3, 4, 5, 7, 9, 13, 14},
                }
                line = json.dumps(record, ensure_ascii=False)
                fh.write(line + "\n")
                conn.execute(
                    "INSERT INTO fixes VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (fix_id, domain_id, domain_name, transport, k1, k2, k3, record["title"], line),
                )
                conn.execute(
                    "INSERT INTO fixes_fts VALUES (?, ?, ?)",
                    (fix_id, record["title"], line),
                )

    conn.commit()
    conn.close()
    assert counter == 10560, f"Expected 10560 fixes, got {counter}"
    print(f"Compiled {counter} deterministic fixes for {TARGET_FBSN} -> {jsonl_path} & {db_path}")


if __name__ == "__main__":
    main()
