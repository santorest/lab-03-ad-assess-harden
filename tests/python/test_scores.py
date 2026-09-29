import shutil
from pathlib import Path

import pytest

from adlab.scores import ScoresError, find_export, parse_pingcastle, table

FIX = Path(__file__).resolve().parent / "fixtures"


def test_parses_the_scores_and_metadata():
    s = parse_pingcastle(FIX / "pingcastle_before.xml")
    assert (s.global_score, s.stale, s.privileged, s.trust, s.anomaly, s.maturity) == (75, 60, 55, 0, 40, 1)
    assert s.domain == "corp.internal" and s.generated.startswith("2026-10-01")


def test_missing_global_score_is_an_error(tmp_path):
    bad = tmp_path / "ad_hc_x.xml"
    bad.write_text("<HealthcheckData><DomainFQDN>corp.internal</DomainFQDN></HealthcheckData>", encoding="utf-8")
    with pytest.raises(ScoresError, match="GlobalScore"):
        parse_pingcastle(bad)


def test_wrong_root_element_is_an_error(tmp_path):
    bad = tmp_path / "ad_hc_x.xml"
    bad.write_text("<Something><GlobalScore>1</GlobalScore></Something>", encoding="utf-8")
    with pytest.raises(ScoresError, match="HealthcheckData"):
        parse_pingcastle(bad)


def test_non_numeric_score_is_an_error(tmp_path):
    bad = tmp_path / "ad_hc_x.xml"
    bad.write_text("<HealthcheckData><GlobalScore>high</GlobalScore></HealthcheckData>", encoding="utf-8")
    with pytest.raises(ScoresError, match="GlobalScore"):
        parse_pingcastle(bad)


def test_table_is_pending_without_exports():
    md = table(None, None)
    rows = [line for line in md.splitlines() if line.startswith("| ") and "Metric" not in line]
    assert rows and all(line.count("Pending") >= 2 for line in rows)


def test_table_shows_before_after_and_change():
    md = table(parse_pingcastle(FIX / "pingcastle_before.xml"), parse_pingcastle(FIX / "pingcastle_after.xml"))
    assert "| Global score (lower is better) | 75 | 20 | −55 |" in md
    assert "| Maturity level (higher is better) | 1 | 3 | +2 |" in md


def test_table_with_only_before_marks_after_pending():
    md = table(parse_pingcastle(FIX / "pingcastle_before.xml"), None)
    assert "| Global score (lower is better) | 75 | Pending | Pending |" in md


def test_find_export_picks_newest_and_handles_empty(tmp_path):
    assert find_export(tmp_path) is None
    assert find_export(tmp_path / "missing") is None
    shutil.copy(FIX / "pingcastle_before.xml", tmp_path / "ad_hc_corp.internal_20261001.xml")
    shutil.copy(FIX / "pingcastle_after.xml", tmp_path / "ad_hc_corp.internal_20261010.xml")
    assert find_export(tmp_path).name == "ad_hc_corp.internal_20261010.xml"
