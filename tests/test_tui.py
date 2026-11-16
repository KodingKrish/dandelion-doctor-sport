import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

import pytest
from textual.widgets import DataTable, Input, Static, TabbedContent

from dandelion_doctor.core.scatter import GOLDEN_VAULT_DUMP_SET
from dandelion_doctor.ui.tui import DandelionDoctorApp


@pytest.mark.asyncio
async def test_app_mounts_and_shows_status():
    app = DandelionDoctorApp()
    async with app.run_test() as pilot:
        body = app.query_one("#status-body", Static)
        rendered = body.render()
        assert "M2006C3LI" in str(rendered)
        assert "6XLFMR9DVK7PCM6H" in str(rendered)


@pytest.mark.asyncio
async def test_vault_tab_lists_all_golden_vault_partitions():
    app = DandelionDoctorApp()
    async with app.run_test() as pilot:
        app.query_one(TabbedContent).active = "tab-vault"
        await pilot.pause()
        table = app.query_one("#vault-table", DataTable)
        assert table.row_count == len(GOLDEN_VAULT_DUMP_SET)


@pytest.mark.asyncio
async def test_catalog_search_populates_table():
    app = DandelionDoctorApp()
    async with app.run_test() as pilot:
        app.query_one(TabbedContent).active = "tab-catalog"
        await pilot.pause()
        search_input = app.query_one("#catalog-search-input", Input)
        search_input.focus()
        await pilot.press(*"persist")
        await pilot.press("enter")
        table = app.query_one("#catalog-table", DataTable)
        assert table.row_count > 0


@pytest.mark.asyncio
async def test_preflight_tab_reports_failure_without_vault():
    app = DandelionDoctorApp()
    async with app.run_test(size=(120, 45)) as pilot:
        app.query_one(TabbedContent).active = "tab-preflight"
        await pilot.pause()
        serial_input = app.query_one("#preflight-serial-input", Input)
        serial_input.focus()
        await pilot.press(*"6XLFMR9DVK7PCM6H")
        battery_input = app.query_one("#preflight-battery-input", Input)
        battery_input.focus()
        await pilot.press(*"4000")
        app.run_preflight()  # invoke the handler directly; layout-independent
        await pilot.pause()
        result = app.query_one("#preflight-result", Static)
        assert "FAILED" in str(result.render())
