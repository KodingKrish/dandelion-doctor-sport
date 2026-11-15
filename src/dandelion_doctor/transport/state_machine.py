"""USB Transport Finite-State Machine (Section 6.1)."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class LinkState(str, Enum):
    DISCONNECTED = "DISCONNECTED"
    BROM = "BROM"
    PRELOADER = "PRELOADER"
    DA_ACTIVE = "DA_ACTIVE"
    META = "META"
    FASTBOOT = "FASTBOOT"
    FASTBOOTD = "FASTBOOTD"
    ADB_OS = "ADB_OS"
    ADB_RECOVERY = "ADB_RECOVERY"
    SIDELOAD = "SIDELOAD"
    DEAD_PHY = "DEAD_PHY"


@dataclass(frozen=True)
class VidPidProfile:
    vid_pid: str
    enum_name: str
    capabilities: str


# Section 6.1 table
STATE_PROFILES: dict[LinkState, VidPidProfile] = {
    LinkState.BROM: VidPidProfile("0E8D:0003", "MTK USB Port",
                                   "Raw SRAM access via Kamakiri2; bypasses locked bootloader"),
    LinkState.PRELOADER: VidPidProfile("0E8D:2000", "MediaTek Preloader USB VCOM",
                                        "~1.5s window at boot; crash-to-BROM or DA handshake"),
    LinkState.DA_ACTIVE: VidPidProfile("0E8D:2001", "MediaTek DA USB VCOM",
                                        "High-speed DRAM-initialized eMMC read/write"),
    LinkState.META: VidPidProfile("0E8D:2007", "MediaTek META Mode",
                                   "Factory NV/IMEI/calibration restore"),
    LinkState.FASTBOOT: VidPidProfile("18D1:D00D", "Android Fastboot",
                                       "Bootloader flashing, slot/partition management"),
    LinkState.ADB_OS: VidPidProfile("2717:FF48", "Xiaomi ADB Interface", "Shell/file/package operations"),
    LinkState.SIDELOAD: VidPidProfile("2717:FF18", "ADB Sideload", "OTA/update-package install"),
}

# Allowed transitions. A transition not listed here is rejected by the FSM.
TRANSITIONS: dict[LinkState, set[LinkState]] = {
    LinkState.DISCONNECTED: {LinkState.BROM, LinkState.PRELOADER, LinkState.FASTBOOT, LinkState.ADB_OS,
                              LinkState.ADB_RECOVERY, LinkState.DEAD_PHY},
    LinkState.BROM: {LinkState.DA_ACTIVE, LinkState.META, LinkState.DISCONNECTED},
    LinkState.PRELOADER: {LinkState.BROM, LinkState.DA_ACTIVE, LinkState.DISCONNECTED},
    LinkState.DA_ACTIVE: {LinkState.DISCONNECTED, LinkState.BROM},
    LinkState.META: {LinkState.DISCONNECTED, LinkState.BROM},
    LinkState.FASTBOOT: {LinkState.FASTBOOTD, LinkState.DISCONNECTED, LinkState.ADB_OS},
    LinkState.FASTBOOTD: {LinkState.FASTBOOT, LinkState.DISCONNECTED, LinkState.ADB_OS},
    LinkState.ADB_OS: {LinkState.ADB_RECOVERY, LinkState.FASTBOOT, LinkState.DISCONNECTED, LinkState.SIDELOAD},
    LinkState.ADB_RECOVERY: {LinkState.ADB_OS, LinkState.SIDELOAD, LinkState.FASTBOOT, LinkState.DISCONNECTED},
    LinkState.SIDELOAD: {LinkState.ADB_RECOVERY, LinkState.DISCONNECTED},
    LinkState.DEAD_PHY: {LinkState.DISCONNECTED},
}


class InvalidTransition(RuntimeError):
    pass


class TransportFSM:
    def __init__(self):
        self.state = LinkState.DISCONNECTED

    def transition(self, new_state: LinkState) -> None:
        allowed = TRANSITIONS.get(self.state, set())
        if new_state != self.state and new_state not in allowed:
            raise InvalidTransition(f"{self.state} -> {new_state} is not a permitted transition")
        self.state = new_state

    def profile(self) -> VidPidProfile | None:
        return STATE_PROFILES.get(self.state)
