"""RuleResolver / Telemetry Signature Engine (Section 4.1, Section 10).

Given live telemetry (usb_vid_pid, dmesg_lines, logcat_lines, getvar_map,
brom_error_code, partition_hashes), ranks matching FIX-* rules from the
compiled 10,560-fix catalog (Section 12) and returns them to the caller for
safety-gated execution.
"""
from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class Telemetry:
    usb_vid_pid: Optional[str] = None
    dmesg_lines: list[str] = field(default_factory=list)
    logcat_lines: list[str] = field(default_factory=list)
    getvar_map: dict[str, str] = field(default_factory=dict)
    brom_error_code: Optional[str] = None
    partition_hashes: dict[str, str] = field(default_factory=dict)


# Section 10: Telemetry Signature Engine — live signature -> candidate FIX-* range
SIGNATURE_MATCHERS: list[tuple[str, re.Pattern, str, tuple[int, int]]] = [
    ("BROM", re.compile(r"DRAM setup failed: unpack requires a buffer of 12 bytes"),
     "2GB Micron EMI table mismatch", (361, 1200)),
    ("BROM", re.compile(r"STATUS_STOR_LIFE_EXHAUST|0xC003001D"),
     "eMMC 5.1 Pre-EOL Exhausted", (3661, 4140)),
    ("FASTBOOT", re.compile(r"__GETVAR_PRODUCT_MISMATCH__"),
     "Wrong firmware/board image risk", (1201, 2400)),
    ("FASTBOOT", re.compile(r"__GETVAR_UNLOCKED_NO__"),
     "Locked bootloader recovery needed", (2401, 2940)),
    ("RECOVERY", re.compile(r"NVDATA is corrupted"),
     "Modem/NV mismatch or corruption", (4141, 5100)),
    ("ADB_OS", re.compile(r"mmc0:.*(error|timeout|CRC)", re.IGNORECASE),
     "eMMC CMD/DATA bus or wear fault", (3661, 4140)),
    ("ADB_OS", re.compile(r"gsm\.version\.baseband\s*=\s*$"),
     "Baseband unknown / md1img/NV fail", (4141, 5100)),
    ("ADB_OS", re.compile(r"02:00:00:00:00:00"),
     "nvram Wi-Fi MAC / MT6631 fault", (5101, 5700)),
    ("ADB_OS", re.compile(r"lowmemorykiller|am_kill"),
     "2GB/3GB RAM thrashing", (8581, 9060)),
]


def fix_id_range(start: int, end: int) -> tuple[str, str]:
    return f"FIX-{start:05d}", f"FIX-{end:05d}"


class RuleResolver:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None

    def _connect(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(self.db_path)
        return self._conn

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def get(self, fix_id: str) -> Optional[dict]:
        cur = self._connect().execute("SELECT payload_json FROM fixes WHERE fix_id = ?", (fix_id,))
        row = cur.fetchone()
        return json.loads(row[0]) if row else None

    def search(self, query: str, limit: int = 25) -> list[dict]:
        cur = self._connect().execute(
            "SELECT payload_json FROM fixes_fts WHERE fixes_fts MATCH ? LIMIT ?",
            (query, limit),
        )
        return [json.loads(r[0]) for r in cur.fetchall()]

    def candidates_in_range(self, start_id: str, end_id: str, limit: int = 50) -> list[dict]:
        cur = self._connect().execute(
            "SELECT payload_json FROM fixes WHERE fix_id BETWEEN ? AND ? ORDER BY fix_id LIMIT ?",
            (start_id, end_id, limit),
        )
        return [json.loads(r[0]) for r in cur.fetchall()]

    def match_telemetry(self, telemetry: Telemetry) -> list[dict]:
        """Runs the Section 10 signature matchers against live telemetry and
        returns ranked candidate fixes (not yet safety-filtered)."""
        text_blob = "\n".join(telemetry.dmesg_lines + telemetry.logcat_lines)
        if telemetry.brom_error_code:
            text_blob += f"\n{telemetry.brom_error_code}"
        for key, value in telemetry.getvar_map.items():
            text_blob += f"\n{key}:{value}"

        # Structured getvar checks (Section 10 FASTBOOT rows): the live
        # signature there is a comparison, not literal text, so it is
        # evaluated directly against the parsed getvar_map rather than regex.
        product = telemetry.getvar_map.get("product")
        if product is not None and product != "dandelion":
            text_blob += "\n__GETVAR_PRODUCT_MISMATCH__"
        unlocked = telemetry.getvar_map.get("unlocked")
        if unlocked is not None and unlocked.lower() == "no":
            text_blob += "\n__GETVAR_UNLOCKED_NO__"

        matches: list[dict] = []
        for transport, pattern, fault_class, (start, end) in SIGNATURE_MATCHERS:
            if pattern.search(text_blob):
                start_id, end_id = fix_id_range(start, end)
                matches.append(
                    {
                        "transport": transport,
                        "fault_class": fault_class,
                        "candidate_range": [start_id, end_id],
                        "sample_candidates": self.candidates_in_range(start_id, end_id, limit=5),
                    }
                )
        return matches
