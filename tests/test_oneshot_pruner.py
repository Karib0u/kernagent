from pathlib import Path

from kernagent.oneshot import build_oneshot_summary


def test_build_oneshot_summary_returns_sections():
    archive = Path(__file__).parent / "fixtures" / "bifrose.snapshot"
    summary = build_oneshot_summary(archive)
    assert "file" in summary
    assert "sections" in summary
    assert summary["file"]["format"]
