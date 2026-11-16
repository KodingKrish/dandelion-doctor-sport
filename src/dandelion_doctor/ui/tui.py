"""Textual TUI dashboard for dandelion-doctor (Section 15 — terminal variant
of the planned desktop dashboard; no Qt/PySide6 dependency required).

Run with: dandelion-doctor-tui   (or: python -m dandelion_doctor.ui.tui)
"""
from __future__ import annotations

from pathlib import Path

from textual import on
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    Static,
    TabbedContent,
    TabPane,
    TextArea,
)

from dandelion_doctor.core.config import load_profile
from dandelion_doctor.core.logger import AuditLogger
from dandelion_doctor.core.rule_engine import RuleResolver, Telemetry
from dandelion_doctor.core.safety import DeviceHandshake, SafetyGatekeeper
from dandelion_doctor.core.scatter import GOLDEN_VAULT_DUMP_SET, PARTITIONS_BY_NAME
from dandelion_doctor.core.vault import GoldenVaultManager
from dandelion_doctor.engines.domains import ALL_ENGINES

PASTEL_LAVENDER = "#c3b1e1"
PASTEL_MINT = "#a8e6cf"
PASTEL_PEACH = "#ffd3b0"
PASTEL_PINK = "#f7cad0"
PASTEL_SKY = "#aed9e0"
PASTEL_RED = "#f6a6a6"
PASTEL_GREEN = "#9fd8b0"
INK = "#2e2a3d"          # dark, warm text color used on pastel backgrounds
BG_DEEP = "#201f2b"      # soft near-black background, not pure black
BG_PANEL = "#28273a"
BG_RAISED = "#32304a"

CSS = f"""
Screen {{
    background: {BG_DEEP};
    color: #e6e1f0;
}}

Header {{
    background: {PASTEL_LAVENDER};
    color: {INK};
    text-style: bold;
}}

Footer {{
    background: {BG_PANEL};
    color: {PASTEL_SKY};
}}

Tabs {{
    background: {BG_PANEL};
}}

Tab {{
    color: #b8b3cc;
}}

Tab:hover {{
    color: {PASTEL_SKY};
}}

Tab.-active {{
    background: {PASTEL_PEACH};
    color: {INK};
    text-style: bold;
}}

TabPane {{
    background: {BG_DEEP};
    padding: 1 1;
}}

#status-grid {{
    height: auto;
    border: round {PASTEL_LAVENDER};
    background: {BG_PANEL};
    padding: 1 2;
    margin-bottom: 1;
}}

.status-row {{
    height: 1;
}}

#fix-detail {{
    border: round {PASTEL_MINT};
    background: {BG_RAISED};
    height: 1fr;
    padding: 1 2;
}}

#diagnose-controls, #preflight-controls {{
    height: auto;
    padding: 1 0;
}}

Input {{
    margin: 0 1 1 0;
    border: round {PASTEL_SKY};
    background: {BG_PANEL};
    color: #e6e1f0;
}}

Input:focus {{
    border: round {PASTEL_PINK};
}}

TextArea {{
    border: round {PASTEL_SKY};
    background: {BG_PANEL};
    margin-bottom: 1;
}}

Button {{
    background: {BG_RAISED};
    color: {PASTEL_SKY};
    border: round {PASTEL_SKY};
}}

Button:hover {{
    background: {PASTEL_SKY};
    color: {INK};
}}

Button.-primary {{
    background: {PASTEL_MINT};
    color: {INK};
    border: round {PASTEL_MINT};
    text-style: bold;
}}

Button.-primary:hover {{
    background: {PASTEL_GREEN};
    color: {INK};
}}

DataTable {{
    height: 1fr;
    background: {BG_PANEL};
    color: #e6e1f0;
}}

DataTable > .datatable--header {{
    background: {PASTEL_LAVENDER};
    color: {INK};
    text-style: bold;
}}

DataTable > .datatable--cursor {{
    background: {PASTEL_PEACH};
    color: {INK};
}}

Label {{
    color: {PASTEL_SKY};
}}

ModalScreen {{
    align: center middle;
}}
"""


class FixDetailScreen(ModalScreen[None]):
    """Modal popup showing a full FIX-* record."""

    BINDINGS = [("escape", "dismiss", "Close")]

    def __init__(self, record: dict) -> None:
        super().__init__()
        self.record = record

    def compose(self) -> ComposeResult:
        lines = "\n".join(f"{k}: {v}" for k, v in self.record.items())
        with Vertical(id="fix-detail"):
            yield Label(f"[b]{self.record.get('fix_id', '?')}[/b]")
            yield Static(lines)
            yield Button("Close (Esc)", id="close-detail")

    @on(Button.Pressed, "#close-detail")
    def close(self) -> None:
        self.dismiss(None)


class DandelionDoctorApp(App):
    """dandelion-doctor TUI — Status / Diagnose / Catalog / Vault / Preflight."""

    CSS = CSS
    TITLE = "dandelion-doctor"
    SUB_TITLE = "Redmi 9A Sport (M2006C3LI) — diagnostic/repair console"
    BINDINGS = [("q", "quit", "Quit"), ("r", "refresh_status", "Refresh")]

    def __init__(self) -> None:
        super().__init__()
        self.profile = load_profile()
        self.resolver = RuleResolver(self.profile.resolve_path(self.profile.paths.catalog_db))
        self.gatekeeper = SafetyGatekeeper(self.profile)
        self.logger = AuditLogger(self.profile.resolve_path(self.profile.paths.logs_dir))

    # ------------------------------------------------------------------ UI
    def compose(self) -> ComposeResult:
        yield Header()
        with TabbedContent():
            with TabPane("Status", id="tab-status"):
                yield from self._compose_status_tab()
            with TabPane("Diagnose", id="tab-diagnose"):
                yield from self._compose_diagnose_tab()
            with TabPane("Catalog", id="tab-catalog"):
                yield from self._compose_catalog_tab()
            with TabPane("Vault", id="tab-vault"):
                yield from self._compose_vault_tab()
            with TabPane("Preflight", id="tab-preflight"):
                yield from self._compose_preflight_tab()
        yield Footer()

    def _compose_status_tab(self) -> ComposeResult:
        with VerticalScroll():
            with Vertical(id="status-grid"):
                yield Static(id="status-body")
            yield Button("Refresh (r)", id="refresh-status")

    def _compose_diagnose_tab(self) -> ComposeResult:
        with VerticalScroll():
            with Horizontal(id="diagnose-controls"):
                yield Input(placeholder="BROM/SPFT error code, e.g. 4032", id="brom-error-input")
                yield Button("Run read-only diagnosis", id="run-diagnose", variant="primary")
            yield Label("Paste captured dmesg/logcat lines below (optional):")
            yield TextArea(id="telemetry-text")
            table = DataTable(id="diagnose-table")
            table.add_columns("Domain", "Diagnosis", "Candidate Fixes")
            yield table

    def _compose_catalog_tab(self) -> ComposeResult:
        with VerticalScroll():
            yield Input(placeholder="Search the 10,560-fix catalog (FTS5)...", id="catalog-search-input")
            table = DataTable(id="catalog-table")
            table.add_columns("Fix ID", "Domain", "Title")
            table.cursor_type = "row"
            yield table

    def _compose_vault_tab(self) -> ComposeResult:
        with VerticalScroll():
            yield Button("Verify Golden Vault now", id="verify-vault", variant="primary")
            table = DataTable(id="vault-table")
            table.add_columns("Partition", "Tier", "Required", "Present & Verified")
            yield table

    def _compose_preflight_tab(self) -> ComposeResult:
        with VerticalScroll():
            with Horizontal(id="preflight-controls"):
                yield Input(placeholder="Connected device serial (FBSN)", id="preflight-serial-input")
                yield Input(placeholder="Battery mV, e.g. 4000", id="preflight-battery-input")
                yield Button("Run Section 13.1 Pre-Flight", id="run-preflight", variant="primary")
            yield Static(id="preflight-result")

    # ------------------------------------------------------------- events
    def on_mount(self) -> None:
        self._refresh_status()
        self._refresh_vault_table()

    @on(Button.Pressed, "#refresh-status")
    def action_refresh_status(self) -> None:
        self._refresh_status()

    def _refresh_status(self) -> None:
        vault_ok, _ = self.gatekeeper.golden_vault_status()
        vault_color = f"bold {PASTEL_GREEN}" if vault_ok else f"bold {PASTEL_RED}"
        vault_text = "VERIFIED" if vault_ok else "NOT VERIFIED"
        body = self.query_one("#status-body", Static)
        body.update(
            f"[b]Device[/b]        : {self.profile.device.marketing_name} ({self.profile.device.model})\n"
            f"[b]Codename[/b]      : {self.profile.device.codename}\n"
            f"[b]Chipset[/b]       : {self.profile.device.chipset} (BROM {self.profile.device.brom_hw_code})\n"
            f"[b]FBSN lock[/b]     : {self.profile.unit_lock.fbsn}\n"
            f"[b]Golden Vault[/b]  : [{vault_color}]{vault_text}[/{vault_color}]\n"
            f"[b]Catalog DB[/b]    : {self.profile.resolve_path(self.profile.paths.catalog_db)}"
        )

    @on(Button.Pressed, "#run-diagnose")
    def run_diagnose(self) -> None:
        brom_error = self.query_one("#brom-error-input", Input).value.strip() or None
        telemetry_text = self.query_one("#telemetry-text", TextArea).text
        lines = telemetry_text.splitlines()
        telemetry = Telemetry(dmesg_lines=lines, logcat_lines=lines, brom_error_code=brom_error)

        table = self.query_one("#diagnose-table", DataTable)
        table.clear()
        for engine_cls in ALL_ENGINES:
            engine = engine_cls(self.resolver, self.gatekeeper, self.logger)
            report = engine.diagnose(telemetry)
            table.add_row(report.domain_name, report.diagnosis, ", ".join(report.matched_fix_ids[:5]) or "-")

    @on(Input.Submitted, "#catalog-search-input")
    def search_catalog_submitted(self, event: Input.Submitted) -> None:
        self._run_catalog_search(event.value)

    @on(Button.Pressed, "#verify-vault")
    def verify_vault(self) -> None:
        self._refresh_vault_table()
        self._refresh_status()

    def _refresh_vault_table(self) -> None:
        table = self.query_one("#vault-table", DataTable)
        table.clear()
        required = set(self.profile.safety.golden_vault_partitions)
        vault = GoldenVaultManager(self.profile, passphrase="")
        manifest = vault.load_manifest() or {"partitions": {}}
        present_ok, _ = vault.verify_at_rest(list(required)) if manifest["partitions"] else (False, [])

        for name in GOLDEN_VAULT_DUMP_SET:
            policy = PARTITIONS_BY_NAME.get(name)
            tier = policy.tier.name if policy else "?"
            entry = manifest["partitions"].get(name)
            if entry is None:
                status, status_color = "missing", f"bold {PASTEL_RED}"
            else:
                ok, _ = vault.verify_at_rest([name])
                status, status_color = ("verified", f"bold {PASTEL_GREEN}") if ok \
                    else ("tampered/corrupted", f"bold {PASTEL_RED}")
            table.add_row(
                name,
                tier,
                "yes" if name in required else "no",
                f"[{status_color}]{status}[/{status_color}]",
            )

    @on(Button.Pressed, "#run-preflight")
    def run_preflight(self) -> None:
        serial = self.query_one("#preflight-serial-input", Input).value.strip() or None
        battery_raw = self.query_one("#preflight-battery-input", Input).value.strip()
        battery_mv = int(battery_raw) if battery_raw.isdigit() else None

        handshake = DeviceHandshake(serialno=serial, battery_mv=battery_mv)
        result = self.gatekeeper.preflight(handshake)
        out = self.query_one("#preflight-result", Static)
        if result.ok:
            out.update(f"[bold {PASTEL_GREEN}]PRE-FLIGHT PASSED[/bold {PASTEL_GREEN}]")
        else:
            out.update(f"[bold {PASTEL_RED}]PRE-FLIGHT FAILED[/bold {PASTEL_RED}]\n"
                        + "\n".join(f"  - {f}" for f in result.failures))

    def _run_catalog_search(self, query: str) -> None:
        table = self.query_one("#catalog-table", DataTable)
        table.clear()
        if not query.strip():
            return
        for hit in self.resolver.search(query, limit=100):
            table.add_row(hit["fix_id"], hit.get("domain_name", "?"), hit["title"])

    @on(DataTable.RowSelected, "#catalog-table")
    def show_fix_detail(self, event: DataTable.RowSelected) -> None:
        row = event.data_table.get_row(event.row_key)
        fix_id = row[0]
        record = self.resolver.get(fix_id)
        if record:
            self.push_screen(FixDetailScreen(record))

    def on_unmount(self) -> None:
        self.resolver.close()


def run() -> None:
    DandelionDoctorApp().run()


if __name__ == "__main__":
    run()
