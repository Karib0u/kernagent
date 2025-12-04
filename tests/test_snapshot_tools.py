from pathlib import Path

from kernagent.snapshot import SnapshotTools


SNAPSHOT_ROOT = Path(__file__).parent / "fixtures" / "bifrose.snapshot"


def test_read_json_loads_meta():
    tools = SnapshotTools(SNAPSHOT_ROOT)
    meta = tools.read_json("meta.json")
    assert "file_name" in meta


def test_get_function_stats_reports_counts():
    tools = SnapshotTools(SNAPSHOT_ROOT)
    stats = tools.get_function_stats()
    assert stats["total"] > 0
    assert stats["with_decomp"] >= 0


def test_search_data_handles_empty_results():
    tools = SnapshotTools(SNAPSHOT_ROOT)
    result = tools.search_data(name_pattern="__unlikely_name__", limit=5)
    assert result["count"] == 0
    assert result["limit"] == 5
