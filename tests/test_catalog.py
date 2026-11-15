import sqlite3
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
JSONL_PATH = REPO_ROOT / "assets" / "catalog" / "fixes_10560.jsonl"
DB_PATH = REPO_ROOT / "assets" / "catalog" / "fixes_10560.db"


def test_jsonl_has_exactly_10560_unique_fix_ids():
    ids = set()
    with JSONL_PATH.open(encoding="utf-8") as fh:
        for line in fh:
            import json
            ids.add(json.loads(line)["fix_id"])
    assert len(ids) == 10560


def test_fix_ids_are_contiguous_FIX_00001_to_FIX_10560():
    expected = {f"FIX-{i:05d}" for i in range(1, 10561)}
    actual = set()
    with JSONL_PATH.open(encoding="utf-8") as fh:
        for line in fh:
            import json
            actual.add(json.loads(line)["fix_id"])
    assert actual == expected


def test_sqlite_db_has_10560_rows_no_duplicates():
    conn = sqlite3.connect(DB_PATH)
    (total,) = conn.execute("SELECT COUNT(*) FROM fixes").fetchone()
    (distinct,) = conn.execute("SELECT COUNT(DISTINCT fix_id) FROM fixes").fetchone()
    conn.close()
    assert total == 10560
    assert distinct == 10560


def test_fts5_queries_resolve():
    conn = sqlite3.connect(DB_PATH)
    for query in ["4032", "NVDATA", "persist", "mt6631", "6XLFMR9DVK7PCM6H"]:
        rows = conn.execute("SELECT fix_id FROM fixes_fts WHERE fixes_fts MATCH ?", (query,)).fetchall()
        assert len(rows) > 0, f"query {query!r} returned no FTS5 matches"
    conn.close()


def test_domain_totals_match_section_3_table():
    expected_totals = {
        1: 360, 2: 840, 3: 1200, 4: 540, 5: 720, 6: 480, 7: 960, 8: 600,
        9: 1080, 10: 600, 11: 1200, 12: 480, 13: 600, 14: 360, 15: 540,
    }
    conn = sqlite3.connect(DB_PATH)
    for domain_id, expected in expected_totals.items():
        (actual,) = conn.execute("SELECT COUNT(*) FROM fixes WHERE domain_id = ?", (domain_id,)).fetchone()
        assert actual == expected, f"domain {domain_id}: expected {expected}, got {actual}"
    conn.close()
