"""CLI (Section 4.1, 15 — PySide6 Desktop Dashboard is Sprint 6; this is the
typer/rich CLI used for Sprints 1-5 and for headless/HIL runs)."""
from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from dandelion_doctor.core.config import load_profile
from dandelion_doctor.core.logger import AuditLogger
from dandelion_doctor.core.rule_engine import RuleResolver, Telemetry
from dandelion_doctor.core.safety import DeviceHandshake, SafetyGatekeeper
from dandelion_doctor.core.scatter import GOLDEN_VAULT_DUMP_SET
from dandelion_doctor.core.vault import GoldenVaultManager
from dandelion_doctor.engines.domains import ALL_ENGINES

app = typer.Typer(help="dandelion-doctor — Redmi 9A Sport (M2006C3LI) diagnostic/repair toolkit")
console = Console()


def _bootstrap():
    profile = load_profile()
    resolver = RuleResolver(profile.resolve_path(profile.paths.catalog_db))
    gatekeeper = SafetyGatekeeper(profile)
    logger = AuditLogger(profile.resolve_path(profile.paths.logs_dir))
    return profile, resolver, gatekeeper, logger


@app.command()
def status():
    """Show device-profile lock status and Golden Vault state."""
    profile, resolver, gatekeeper, logger = _bootstrap()
    table = Table(title=f"dandelion-doctor — {profile.device.marketing_name} ({profile.device.model})")
    table.add_column("Check")
    table.add_column("Value")
    table.add_row("FBSN lock", profile.unit_lock.fbsn)
    table.add_row("Chipset", f"{profile.device.chipset} (BROM {profile.device.brom_hw_code})")
    table.add_row("Golden Vault verified", str(gatekeeper.golden_vault_present_and_verified()))
    table.add_row("Catalog DB", str(profile.resolve_path(profile.paths.catalog_db)))
    console.print(table)
    resolver.close()


@app.command()
def diagnose(
    dmesg: Path = typer.Option(None, help="File containing captured dmesg output"),
    logcat: Path = typer.Option(None, help="File containing captured logcat output"),
    brom_error: str = typer.Option(None, help="Observed BROM/SPFT error code, e.g. 4032"),
):
    """Read-only HIL run (Section 14): run all 15 engines against supplied
    telemetry and report matching FIX-* candidates. Writes nothing."""
    profile, resolver, gatekeeper, logger = _bootstrap()
    telemetry = Telemetry(
        dmesg_lines=dmesg.read_text().splitlines() if dmesg else [],
        logcat_lines=logcat.read_text().splitlines() if logcat else [],
        brom_error_code=brom_error,
    )

    table = Table(title="Diagnosis (read-only, zero writes)")
    table.add_column("Domain")
    table.add_column("Diagnosis")
    table.add_column("Candidate Fixes")

    for engine_cls in ALL_ENGINES:
        engine = engine_cls(resolver, gatekeeper, logger)
        report = engine.diagnose(telemetry)
        table.add_row(report.domain_name, report.diagnosis, ", ".join(report.matched_fix_ids[:5]) or "-")

    console.print(table)
    resolver.close()


@app.command()
def search(query: str, limit: int = 10):
    """Full-text search the 10,560-fix catalog (FTS5)."""
    profile, resolver, gatekeeper, logger = _bootstrap()
    for hit in resolver.search(query, limit=limit):
        console.print(f"[bold]{hit['fix_id']}[/bold] — {hit['title']}")
    resolver.close()


@app.command()
def show(fix_id: str):
    """Show the full record for one FIX-* id."""
    profile, resolver, gatekeeper, logger = _bootstrap()
    record = resolver.get(fix_id)
    if record is None:
        console.print(f"[red]{fix_id} not found[/red]")
    else:
        for k, v in record.items():
            console.print(f"[bold]{k}[/bold]: {v}")
    resolver.close()


@app.command()
def preflight(battery_mv: int = typer.Option(None), serialno: str = typer.Option(None)):
    """Run the Section 13.1 Mandatory Pre-Flight Checklist and report pass/fail."""
    profile, resolver, gatekeeper, logger = _bootstrap()
    handshake = DeviceHandshake(serialno=serialno, battery_mv=battery_mv)
    result = gatekeeper.preflight(handshake)
    if result.ok:
        console.print("[green]PRE-FLIGHT PASSED[/green]")
    else:
        console.print("[red]PRE-FLIGHT FAILED[/red]")
        for failure in result.failures:
            console.print(f"  - {failure}")
    resolver.close()


if __name__ == "__main__":
    app()
