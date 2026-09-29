from pathlib import Path

import pytest

from adlab.findings import FindingsError, load_findings, main, validate

ROOT = Path(__file__).resolve().parents[2]

GOOD = {
    "id": "F01", "title": "Service account in Domain Admins", "weakness_ref": "W01", "severity": "critical",
    "evidence": "Expected: PingCastle privileged-group rule; BloodHound path to Domain Admins",
    "impact": "Full domain compromise if the service or its host is breached",
    "remediation": "Move the service to a gMSA with least privilege",
    "script": "scripts/harden/Convert-ServiceAccountToGmsa.ps1", "status": "open", "verified_by": "",
}


def test_valid_register_loads():
    assert validate([GOOD])[0].severity == "critical"


@pytest.mark.parametrize(("change", "msg"), [
    ({"severity": "urgent"}, "severity"), ({"status": "done"}, "status"), ({"id": ""}, "id"),
    ({"weakness_ref": "X1"}, "weakness_ref"), ({"remediation": ""}, "remediation")])
def test_invalid_fields_are_rejected(change, msg):
    with pytest.raises(FindingsError, match=msg):
        validate([{**GOOD, **change}])


def test_fixed_without_verification_is_rejected():
    with pytest.raises(FindingsError, match="verified_by"):
        validate([{**GOOD, "status": "fixed", "verified_by": ""}])


def test_fixed_with_verification_is_accepted():
    f = validate([{**GOOD, "status": "fixed", "verified_by": "PingCastle after-scan 2026-10-10"}])[0]
    assert f.status == "fixed"


def test_duplicate_ids_are_rejected():
    with pytest.raises(FindingsError, match="duplicate"):
        validate([GOOD, GOOD])


def test_script_must_exist_when_checked(tmp_path):
    with pytest.raises(FindingsError, match="script"):
        validate([GOOD], repo_root=tmp_path)


def test_register_must_be_a_list():
    with pytest.raises(FindingsError, match="list"):
        validate({"F01": GOOD})


def test_repo_register_is_valid_and_all_open():
    findings = load_findings(ROOT / "findings" / "findings.yaml")
    assert [f.weakness_ref for f in findings] == [f"W{i:02d}" for i in range(1, 12)]
    assert all(f.status == "open" for f in findings)  # nothing is fixed until the lab proves it


def test_cli_summary(capsys):
    assert main([str(ROOT / "findings" / "findings.yaml")]) == 0
    assert "OK: 11 findings (11 open, 0 fixed, 0 accepted)" in capsys.readouterr().out
