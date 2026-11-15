import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(REPO_ROOT / "tests"))

from dandelion_doctor.core.rule_engine import RuleResolver, Telemetry
from mocks import MockADB, MockBROM, MockFastboot

DB_PATH = REPO_ROOT / "assets" / "catalog" / "fixes_10560.db"


def resolver():
    return RuleResolver(DB_PATH)


def test_dram_setup_failed_matches_domain_2_range():
    brom = MockBROM.dram_setup_failed_trace()
    telemetry = Telemetry(brom_error_code=brom.recorded_stderr)
    r = resolver()
    matches = r.match_telemetry(telemetry)
    r.close()
    assert any(m["candidate_range"] == ["FIX-00361", "FIX-01200"] for m in matches)


def test_nvdata_corrupted_matches_domain_7_range():
    brom = MockBROM.nvdata_corrupted_trace()
    telemetry = Telemetry(logcat_lines=[brom.recorded_stderr])
    r = resolver()
    matches = r.match_telemetry(telemetry)
    r.close()
    assert any(m["candidate_range"] == ["FIX-04141", "FIX-05100"] for m in matches)


def test_wrong_product_getvar_matches_domain_3_range():
    fb = MockFastboot(getvar_responses={"product": "angelica"})
    telemetry = Telemetry(getvar_map={"product": fb.getvar("product")})
    r = resolver()
    matches = r.match_telemetry(telemetry)
    r.close()
    assert any(m["candidate_range"] == ["FIX-01201", "FIX-02400"] for m in matches)


def test_generic_wifi_mac_matches_domain_8_range():
    adb = MockADB(logcat_lines=["wlan0: link address 02:00:00:00:00:00"])
    telemetry = Telemetry(logcat_lines=adb.logcat_dump())
    r = resolver()
    matches = r.match_telemetry(telemetry)
    r.close()
    assert any(m["candidate_range"] == ["FIX-05101", "FIX-05700"] for m in matches)


def test_fts5_search_returns_well_formed_records():
    r = resolver()
    hits = r.search("persist")
    r.close()
    assert hits
    for hit in hits:
        assert hit["fix_id"].startswith("FIX-")
        assert "title" in hit
