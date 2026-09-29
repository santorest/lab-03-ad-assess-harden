"""PingCastle before/after scores for the write-up and the report.

    python -m adlab.scores          # reads the newest ad_hc_*.xml in evidence/before and evidence/after

PingCastle scores are "risk points": lower is better (0 is best). Maturity level runs 1-5: higher is better.
Missing exports are reported as "Pending", never as a number.
"""

import sys
import xml.etree.ElementTree as ET  # noqa: S405  # nosec B405 - parses the owner's own local PingCastle exports
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# (label, attribute, higher_is_better)
METRICS = [
    ("Global score (lower is better)", "global_score", False),
    ("Stale objects", "stale", False),
    ("Privileged accounts", "privileged", False),
    ("Trusts", "trust", False),
    ("Anomalies", "anomaly", False),
    ("Maturity level (higher is better)", "maturity", True),
]


class ScoresError(ValueError):
    pass


@dataclass(frozen=True)
class Scores:
    global_score: int
    stale: int
    privileged: int
    trust: int
    anomaly: int
    maturity: int
    domain: str
    generated: str


def _int(root, tag: str, path: Path) -> int:
    node = root.find(tag)
    if node is None or node.text is None:
        raise ScoresError(f"{path.name}: {tag} not found - is this a PingCastle health-check export?")
    try:
        return int(node.text.strip())
    except ValueError as exc:
        raise ScoresError(f"{path.name}: {tag} is not a number ({node.text!r})") from exc


def parse_pingcastle(path: Path) -> Scores:
    try:
        root = ET.parse(path).getroot()  # noqa: S314  # nosec B314 - local file produced by the owner
    except ET.ParseError as exc:
        raise ScoresError(f"{Path(path).name}: not valid XML ({exc})") from exc
    path = Path(path)
    if root.tag != "HealthcheckData":
        raise ScoresError(f"{path.name}: root element is <{root.tag}>, expected <HealthcheckData>")
    return Scores(
        global_score=_int(root, "GlobalScore", path),
        stale=_int(root, "StaleObjectsScore", path),
        privileged=_int(root, "PrivilegiedGroupScore", path),  # PingCastle's own spelling
        trust=_int(root, "TrustScore", path),
        anomaly=_int(root, "AnomalyScore", path),
        maturity=_int(root, "MaturityLevel", path),
        domain=(root.findtext("DomainFQDN") or "").strip(),
        generated=(root.findtext("GenerationDate") or "").strip(),
    )


def find_export(folder: Path) -> Path | None:
    folder = Path(folder)
    if not folder.is_dir():
        return None
    exports = sorted(folder.glob("ad_hc_*.xml"))
    return exports[-1] if exports else None


def _change(before: int, after: int) -> str:
    diff = after - before
    if diff == 0:
        return "0"
    return f"+{diff}" if diff > 0 else f"−{abs(diff)}"


def rows(before: Scores | None, after: Scores | None) -> list[tuple[str, str, str, str]]:
    """(metric, before, after, change) as display strings; "Pending" wherever an export is missing."""
    out = []
    for label, attr, _higher in METRICS:
        b = getattr(before, attr) if before else None
        a = getattr(after, attr) if after else None
        change = _change(b, a) if b is not None and a is not None else "Pending"
        out.append((label, "Pending" if b is None else str(b), "Pending" if a is None else str(a), change))
    return out


def table(before: Scores | None, after: Scores | None) -> str:
    lines = ["| Metric | Before | After | Change |", "|---|---|---|---|"]
    lines += [f"| {m} | {b} | {a} | {c} |" for m, b, a, c in rows(before, after)]
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    before_file = find_export(ROOT / "evidence" / "before")
    after_file = find_export(ROOT / "evidence" / "after")
    try:
        before = parse_pingcastle(before_file) if before_file else None
        after = parse_pingcastle(after_file) if after_file else None
    except ScoresError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(table(before, after))
    return 0


if __name__ == "__main__":
    sys.exit(main())
