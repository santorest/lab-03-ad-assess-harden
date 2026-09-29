"""Findings register: findings/findings.yaml is the source of truth for the findings table and the report.

    python -m adlab.findings findings/findings.yaml [--check-scripts]

A finding can only be "fixed" when `verified_by` says how the fix was proven (e.g. the after-scan).
"""

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
SEVERITIES = ("critical", "high", "medium", "low")
STATUSES = ("open", "fixed", "accepted")
REQUIRED_TEXT = ("id", "title", "evidence", "impact", "remediation")


class FindingsError(ValueError):
    pass


@dataclass(frozen=True)
class Finding:
    id: str
    title: str
    weakness_ref: str
    severity: str
    evidence: str
    impact: str
    remediation: str
    script: str
    status: str
    verified_by: str


def validate(raw, repo_root: Path | None = None) -> list[Finding]:
    """Validate the register. With repo_root, every referenced script must exist under it."""
    if not isinstance(raw, list):
        raise FindingsError("the register must be a list of findings")
    findings, seen = [], set()
    for i, item in enumerate(raw, 1):
        if not isinstance(item, dict):
            raise FindingsError(f"entry {i}: must be a mapping")
        where = f"finding {item.get('id') or i}"
        for key in REQUIRED_TEXT:
            if not str(item.get(key) or "").strip():
                raise FindingsError(f"{where}: {key} is required")
        if not re.fullmatch(r"W\d{2}", str(item.get("weakness_ref", ""))):
            raise FindingsError(f"{where}: weakness_ref must look like W01")
        if item.get("severity") not in SEVERITIES:
            raise FindingsError(f"{where}: severity must be one of {', '.join(SEVERITIES)}")
        if item.get("status") not in STATUSES:
            raise FindingsError(f"{where}: status must be one of {', '.join(STATUSES)}")
        if item["status"] == "fixed" and not str(item.get("verified_by") or "").strip():
            raise FindingsError(f"{where}: a fixed finding needs verified_by (how the fix was proven)")
        script = str(item.get("script") or "")
        if repo_root is not None and script and not (Path(repo_root) / script).is_file():
            raise FindingsError(f"{where}: script {script} does not exist")
        if item["id"] in seen:
            raise FindingsError(f"{where}: duplicate id")
        seen.add(item["id"])
        findings.append(Finding(
            id=str(item["id"]), title=str(item["title"]), weakness_ref=item["weakness_ref"],
            severity=item["severity"], evidence=str(item["evidence"]), impact=str(item["impact"]),
            remediation=str(item["remediation"]), script=script, status=item["status"],
            verified_by=str(item.get("verified_by") or ""),
        ))
    return findings


def load_findings(path: Path, repo_root: Path | None = None) -> list[Finding]:
    return validate(yaml.safe_load(Path(path).read_text(encoding="utf-8")), repo_root)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Validate the findings register.")
    parser.add_argument("path", type=Path)
    parser.add_argument("--check-scripts", action="store_true", help="also require every referenced script to exist")
    args = parser.parse_args(argv)
    try:
        findings = load_findings(args.path, REPO_ROOT if args.check_scripts else None)
    except FindingsError as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return 1
    counts = {s: sum(f.status == s for f in findings) for s in STATUSES}
    summary = f"{counts['open']} open, {counts['fixed']} fixed, {counts['accepted']} accepted"
    print(f"OK: {len(findings)} findings ({summary})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
