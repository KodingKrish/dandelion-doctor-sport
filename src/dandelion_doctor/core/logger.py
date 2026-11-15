"""Immutable Audit Logging (Section 13.4).

Every USB transition, register dump, command, and SHA-256 checksum is
appended to logs/audit_<timestamp>.jsonl. Append-only: no update/delete API
is exposed on purpose.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class AuditLogger:
    def __init__(self, logs_dir: Path):
        self.logs_dir = logs_dir
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        self.log_path = self.logs_dir / f"audit_{ts}.jsonl"

    def _append(self, event_type: str, payload: dict[str, Any]) -> None:
        record = {
            "event_id": str(uuid.uuid4()),
            "ts_utc": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            **payload,
        }
        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")

    def usb_transition(self, old_state: str, new_state: str, vid_pid: str) -> None:
        self._append("usb_transition", {"old_state": old_state, "new_state": new_state, "vid_pid": vid_pid})

    def register_dump(self, name: str, value_hex: str) -> None:
        self._append("register_dump", {"register": name, "value_hex": value_hex})

    def command(self, cmd: str, args: dict[str, Any]) -> None:
        self._append("command", {"cmd": cmd, "args": args})

    def checksum(self, label: str, sha256_hex: str) -> None:
        self._append("checksum", {"label": label, "sha256": sha256_hex})

    def fix_applied(self, fix_id: str, result: str, detail: str = "") -> None:
        self._append("fix_applied", {"fix_id": fix_id, "result": result, "detail": detail})

    def rollback(self, snapshot_id: str, reason: str) -> None:
        self._append("rollback", {"snapshot_id": snapshot_id, "reason": reason})
