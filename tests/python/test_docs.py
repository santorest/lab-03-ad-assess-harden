"""The weakness catalogue and guides must stay in step with the findings register."""

import re
from pathlib import Path

from adlab.findings import load_findings

ROOT = Path(__file__).resolve().parents[2]


def test_every_weakness_in_the_register_is_documented():
    catalogue = (ROOT / "docs" / "weaknesses.md").read_text(encoding="utf-8")
    documented = set(re.findall(r"^\| (W\d\d) \|", catalogue, flags=re.M))
    referenced = {f.weakness_ref for f in load_findings(ROOT / "findings" / "findings.yaml")}
    assert referenced <= documented, f"undocumented: {sorted(referenced - documented)}"


def test_assessment_guides_exist_for_each_tool():
    for guide in ("01-pingcastle.md", "02-bloodhound.md", "03-policy-analyzer.md"):
        assert (ROOT / "docs" / "assessment" / guide).is_file(), guide


def test_siem_checks_cover_the_key_events():
    text = (ROOT / "docs" / "siem-checks.md").read_text(encoding="utf-8")
    for event_id in ("4728", "4732", "4625", "4740", "4662"):
        assert event_id in text, event_id
