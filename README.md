# dandelion-doctor

Deterministic diagnostic/repair toolkit for a single **Xiaomi Redmi 9A Sport
(`M2006C3LI`, codename `dandelion`)**, locked to serial `FBSN 6XLFMR9DVK7PCM6H`.

Built from the Master Engineering Plan, section by section:

| Section | What it is | Where it lives |
| :-- | :-- | :-- |
| 1 | Silicon/PCB profile | `config/device_profile.yaml` |
| 2 | Unit-binding, ethics & safety policy | `config/device_profile.yaml`, `core/safety.py` |
| 3 / 12 | 10,560-fix taxonomy & generator | `scripts/build_fix_catalog.py` → `assets/catalog/` |
| 4–5 | Architecture & repo layout | this tree |
| 6 | USB transport & FSM | `transport/` |
| 7 | Golden NV Vault (Phase 0 backup) | `core/safety.py`, `backups/<FBSN>/golden_nv_vault/` |
| 8 | 40-partition map & repair tiers | `core/scatter.py` |
| 9 | 15 deep subsystem repair engines | `engines/domains.py` |
| 10 | Telemetry signature engine | `core/rule_engine.py` |
| 11 | Fix schema | one JSON object per line in `assets/catalog/fixes_10560.jsonl` |
| 13 | Safety gatekeeper & audit log | `core/safety.py`, `core/logger.py` |
| 14 | Tests & mock transport harness | `tests/` |
| 15 | CLI entrypoint | `ui/cli.py` |

## Quick start

```bash
pip install -e ".[dev]"
python3 scripts/build_fix_catalog.py        # regenerates the 10,560-fix catalog
pytest tests/ -v                            # catalog integrity + safety + rule-engine tests
dandelion-doctor status                     # FBSN lock / Golden Vault status
dandelion-doctor search "persist"           # FTS5 search over the catalog
dandelion-doctor diagnose --dmesg dmesg.txt --brom-error 4032   # read-only, zero writes
dandelion-doctor preflight --battery-mv 4000 --serialno 6XLFMR9DVK7PCM6H
```

## What's implemented vs. stubbed

This is Sprint 1–3 of the plan's own roadmap (Section 15):

- **Fully implemented and tested:** the 10,560-fix catalog generator and its
  SQLite/FTS5 + JSONL outputs (exactly matching Section 3's domain totals);
  the Safety Gatekeeper's full pre-flight checklist (FBSN lock, Golden Vault
  SHA-256 verification, preloader quarantine, battery/disk checks, identifier
  ethics boundary); the USB FSM and its allowed-transition graph; the 40-partition
  safety-tier map; the Section 10 telemetry signature engine; the 15 domain
  engines' read-only `diagnose()` path; the typer/rich CLI; a mock transport
  harness that replays real recorded `mtkclient` traces offline.
- **Thin, auditable wrappers (not reimplemented):** `transport/brom.py` and
  `transport/meta.py` shell out to the operator's own installed copy of
  [`bkerler/mtkclient`](https://github.com/bkerler/mtkclient) (per Section 4.1)
  rather than reimplementing BootROM exploitation — dandelion-doctor's job is
  orchestration, safety-gating and audit logging around that existing,
  community-maintained tool, exactly as the plan specifies.
- **Not yet implemented (next sprints, per Section 15):** the actual
  partition-write execution paths inside each engine (`execute_fix()` is
  present and safety-gated in `engines/base.py`, but each engine's real
  flash/repair steps are a later sprint), the PySide6 GUI (Sprint 6), and the
  pinned platform-tools/preloader/DA binaries under `assets/` (binary blobs —
  the repo ships the directory layout and policy for them, not the blobs
  themselves, since those come from the device's own stock firmware).

## Safety

Nothing destructive runs until `SafetyGatekeeper.preflight()` passes:
FBSN match, verified Golden Vault, minimum battery voltage (or
`--battery-disconnected` in Testpoint BROM mode), and minimum free disk
space. The `preloader` partition stays read-only unless both
`--repair-preloader` and a confirmed dead-boot state are set. Identifier
(IMEI/MAC/serial) recovery only ever restores from this unit's own Golden
Vault or its original box/SIM-tray/PCB markings — spoofing, cloning, and
FRP/Mi-Account bypass are hard-disabled in the ethics policy and checked by
`SafetyGatekeeper.identifier_operation_allowed()`.
