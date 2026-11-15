"""Common interface for the 15 Deep Subsystem Repair Engines (Section 9)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from dandelion_doctor.core.logger import AuditLogger
from dandelion_doctor.core.rule_engine import RuleResolver, Telemetry
from dandelion_doctor.core.safety import SafetyGatekeeper


@dataclass
class EngineReport:
    domain_id: int
    domain_name: str
    matched_fix_ids: list[str]
    diagnosis: str
    dry_run: bool = True
    blocked_reason: Optional[str] = None


class RepairEngine:
    """Base class for all Domain 01-15 engines.

    Subclasses set DOMAIN_ID / DOMAIN_NAME / FIX_RANGE (inclusive, 1-indexed
    against the 10,560-entry catalog, matching Section 3's table) and
    implement diagnose().
    """

    DOMAIN_ID: int = 0
    DOMAIN_NAME: str = "UNSET"
    FIX_RANGE: tuple[int, int] = (0, 0)

    def __init__(self, resolver: RuleResolver, gatekeeper: SafetyGatekeeper, logger: AuditLogger):
        self.resolver = resolver
        self.gatekeeper = gatekeeper
        self.logger = logger

    def _range_ids(self) -> tuple[str, str]:
        start, end = self.FIX_RANGE
        return f"FIX-{start:05d}", f"FIX-{end:05d}"

    def search(self, query: str, limit: int = 10) -> list[dict]:
        start_id, end_id = self._range_ids()
        hits = self.resolver.search(query, limit=limit * 3)
        return [h for h in hits if start_id <= h["fix_id"] <= end_id][:limit]

    def diagnose(self, telemetry: Telemetry) -> EngineReport:  # pragma: no cover - overridden
        raise NotImplementedError

    def execute_fix(self, fix_id: str, dry_run: bool = True) -> EngineReport:
        """Safety-gated execution entrypoint. Real partition writes are
        implemented per-engine in a later sprint (Section 15, Sprint 4-5);
        this base always honours dry_run and the Golden Vault / FBSN
        preflight before anything destructive could run."""
        fix = self.resolver.get(fix_id)
        if fix is None:
            return EngineReport(self.DOMAIN_ID, self.DOMAIN_NAME, [], f"Unknown fix_id {fix_id}", dry_run)

        if fix.get("requires_golden_vault") and not self.gatekeeper.golden_vault_present_and_verified():
            self.logger.fix_applied(fix_id, "BLOCKED", "Golden Vault missing/unverified")
            return EngineReport(
                self.DOMAIN_ID, self.DOMAIN_NAME, [fix_id],
                fix["title"], dry_run, blocked_reason="Golden Vault missing or SHA-256 verification failed",
            )

        self.logger.fix_applied(fix_id, "DRY_RUN" if dry_run else "PLANNED", fix["title"])
        return EngineReport(self.DOMAIN_ID, self.DOMAIN_NAME, [fix_id], fix["title"], dry_run)
