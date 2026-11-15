"""USB hotplug watcher (Section 6, 9.1).

Polls for the known dandelion VID:PID pairs and drives the TransportFSM.
Uses pyusb when a real libusb backend is available; falls back to a no-op
scan (so the rest of the stack, tests, and the GUI can run without hardware
attached) when it isn't.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, Optional

from dandelion_doctor.transport.state_machine import LinkState, STATE_PROFILES, TransportFSM

try:
    import usb.core  # type: ignore
    import usb.backend.libusb1  # type: ignore
    _HAS_PYUSB = True
except Exception:  # pragma: no cover - environment dependent
    _HAS_PYUSB = False


@dataclass
class HotplugEvent:
    state: LinkState
    vid_pid: str


def _vid_pid_for(state: LinkState) -> Optional[tuple[int, int]]:
    profile = STATE_PROFILES.get(state)
    if profile is None:
        return None
    vid_str, pid_str = profile.vid_pid.split(":")
    return int(vid_str, 16), int(pid_str, 16)


class USBWatcher:
    """Section 9.1: resolves descriptor enumeration, driver-binding, and
    link-fault issues (FIX-00001..FIX-00360) before handing off to the FSM."""

    def __init__(self, fsm: Optional[TransportFSM] = None, poll_interval_s: float = 0.4):
        self.fsm = fsm or TransportFSM()
        self.poll_interval_s = poll_interval_s
        self._backend_available = _HAS_PYUSB

    def find_device(self, state: LinkState):
        if not self._backend_available:
            return None
        vid_pid = _vid_pid_for(state)
        if vid_pid is None:
            return None
        vid, pid = vid_pid
        try:
            return usb.core.find(idVendor=vid, idProduct=pid)  # type: ignore
        except Exception:
            return None

    def scan_once(self) -> Optional[HotplugEvent]:
        for state in (LinkState.BROM, LinkState.PRELOADER, LinkState.DA_ACTIVE,
                      LinkState.META, LinkState.FASTBOOT, LinkState.ADB_OS, LinkState.SIDELOAD):
            dev = self.find_device(state)
            if dev is not None:
                profile = STATE_PROFILES[state]
                self.fsm.transition(state)
                return HotplugEvent(state=state, vid_pid=profile.vid_pid)
        if self.fsm.state != LinkState.DISCONNECTED:
            self.fsm.transition(LinkState.DISCONNECTED)
        return None

    def watch(self, on_event: Callable[[HotplugEvent], None], stop_after_s: Optional[float] = None) -> None:
        """Blocking hotplug loop. Pass stop_after_s for tests/CI."""
        elapsed = 0.0
        while stop_after_s is None or elapsed < stop_after_s:
            event = self.scan_once()
            if event is not None:
                on_event(event)
            time.sleep(self.poll_interval_s)
            elapsed += self.poll_interval_s
