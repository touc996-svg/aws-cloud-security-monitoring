"""The recruiter-facing demo must keep working and must not leak real identifiers."""
import re
import runpy
from pathlib import Path

DEMO = Path(__file__).resolve().parents[1] / "demo"


def test_demo_builds_one_cross_cloud_incident(capsys):
    code = None
    try:
        runpy.run_path(str(DEMO / "run_demo.py"), run_name="__main__")
    except SystemExit as exc:
        code = exc.code
    out = capsys.readouterr().out
    assert code == 0, out
    assert "clouds=aws,azure,gcp" in out
    assert "duplicates collapsed .... 1" in out
    assert "records ingested ........ 5  (quarantined: 0)" in out
    assert out.count("Left alone") == 1 and "Unprotected port" in out


def test_demo_data_uses_only_fake_identifiers():
    text = "\n".join(p.read_text() for p in (DEMO / "data").iterdir())
    for real in ("803872867382", "81b0daa5", "touc996"):
        assert real not in text
    assert set(re.findall(r"\b\d{12}\b", text)) <= {"111111111111", "111222333444"}
