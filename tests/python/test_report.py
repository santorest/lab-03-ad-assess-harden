from datetime import date
from pathlib import Path

from adlab.findings import validate
from adlab.report import is_draft, render_html
from adlab.scores import parse_pingcastle

FIX = Path(__file__).resolve().parent / "fixtures"
BEFORE = parse_pingcastle(FIX / "pingcastle_before.xml")
AFTER = parse_pingcastle(FIX / "pingcastle_after.xml")


def finding(id_, severity, status="open", verified_by="", evidence="Expected evidence"):
    return {"id": id_, "title": f"Finding {id_}", "weakness_ref": "W01", "severity": severity, "evidence": evidence,
            "impact": "Impact text", "remediation": "Fix text", "script": "", "status": status,
            "verified_by": verified_by}


def test_draft_when_scores_are_missing():
    f = validate([finding("F01", "high", "fixed", "after-scan")])
    assert is_draft(f, None, None)
    assert "Draft — pending lab results" in render_html(f, None, None, date(2026, 10, 1))


def test_draft_when_a_finding_is_still_open():
    assert is_draft(validate([finding("F01", "high")]), BEFORE, AFTER)


def test_final_when_scored_and_everything_verified():
    f = validate([finding("F01", "high", "fixed", "PingCastle after-scan"),
                  finding("F02", "low", "accepted", "Risk accepted by management")])
    assert not is_draft(f, BEFORE, AFTER)
    assert "Draft" not in render_html(f, BEFORE, AFTER, date(2026, 10, 10))


def test_executive_summary_counts_by_severity():
    f = validate([finding("F01", "critical"), finding("F02", "high"), finding("F03", "high")])
    html = render_html(f, None, None, date(2026, 10, 1))
    assert "<td>Critical</td><td>1</td>" in html and "<td>High</td><td>2</td>" in html


def test_findings_are_sorted_by_severity():
    f = validate([finding("F01", "low"), finding("F02", "critical"), finding("F03", "medium")])
    html = render_html(f, None, None, date(2026, 10, 1))
    assert html.index("F02") < html.index("F03") < html.index("F01")


def test_finding_text_is_escaped():
    f = validate([finding("F01", "high", evidence="<script>alert(1)</script>")])
    html = render_html(f, None, None, date(2026, 10, 1))
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html


def test_scores_table_is_included():
    html = render_html(validate([finding("F01", "high")]), BEFORE, AFTER, date(2026, 10, 10))
    assert "<td>Global score (lower is better)</td><td>75</td><td>20</td><td>−55</td>" in html


def test_draft_summary_does_not_claim_an_assessment_ran():
    html = render_html(validate([finding("F01", "critical")]), None, None, date(2026, 10, 1))
    assert "recorded" not in html and "The assessment plan expects 1 finding" in html


def test_final_summary_reports_recorded_findings():
    f = validate([finding("F01", "high", "fixed", "after-scan")])
    assert "The assessment recorded 1 finding" in render_html(f, BEFORE, AFTER, date(2026, 10, 10))
