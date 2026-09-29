"""Generate the assessment report from the findings register and the PingCastle exports.

    python -m adlab.report          # writes report/report.html
    python -m adlab.report --pdf    # also report/report.pdf (needs Microsoft Edge or Chromium)

The report is marked "Draft — pending lab results" until both PingCastle exports exist and every finding is
fixed or accepted with verification. All text from the register is HTML-escaped.
"""

import argparse
import shutil
import subprocess  # nosec B404 - only runs a local browser binary to print the report to PDF
import sys
from datetime import date
from html import escape
from pathlib import Path
from string import Template

from adlab.findings import SEVERITIES, Finding, load_findings
from adlab.scores import Scores, ScoresError, find_export, parse_pingcastle, rows

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "report" / "template.html"
BROWSERS = [
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    "msedge", "microsoft-edge", "chromium", "chromium-browser", "google-chrome",
]


def is_draft(findings: list[Finding], before: Scores | None, after: Scores | None) -> bool:
    if before is None or after is None:
        return True
    return any(f.status == "open" or not f.verified_by for f in findings)


def _cells(*values: str) -> str:
    return "<tr>" + "".join(f"<td>{escape(v)}</td>" for v in values) + "</tr>"


def render_html(findings: list[Finding], before: Scores | None, after: Scores | None, generated: date) -> str:
    ordered = sorted(findings, key=lambda f: (SEVERITIES.index(f.severity), f.id))
    counts = {s: [f for f in findings if f.severity == s] for s in SEVERITIES}
    open_total = sum(f.status == "open" for f in findings)
    draft = is_draft(findings, before, after)
    noun = "finding" if len(findings) == 1 else "findings"
    lead = (f"The assessment plan expects {len(findings)} {noun} in the baseline domain" if draft
            else f"The assessment recorded {len(findings)} {noun}")
    summary = (f"{lead}; {open_total} still open. {len(counts['critical'])} rated critical: each could lead to full "
               "control of the domain.")
    findings_html = "\n".join(
        f'<div class="finding"><h3>{escape(f.id)} — {escape(f.title)} '
        f'<span class="sev {f.severity}">({escape(f.severity)})</span></h3>'
        f"<p><strong>Evidence:</strong> {escape(f.evidence)}</p>"
        f"<p><strong>Business impact:</strong> {escape(f.impact)}</p>"
        f"<p><strong>Remediation:</strong> {escape(f.remediation)}</p>"
        f"<p class=\"muted\">Status: {escape(f.status)}"
        f"{' · verified by: ' + escape(f.verified_by) if f.verified_by else ''}</p></div>"
        for f in ordered
    )
    banner = ('<p class="draft">Draft — pending lab results. Scores and fixes are not yet measured; this document '
              "shows the assessment plan and expected findings.</p>") if draft else ""
    return Template(TEMPLATE.read_text(encoding="utf-8")).substitute(
        generated=escape(generated.isoformat()),
        draft_banner=banner,
        summary_text=escape(summary),
        severity_rows="".join(
            _cells(s.capitalize(), str(len(items)), str(sum(f.status == "open" for f in items)))
            for s, items in counts.items()),
        score_rows="".join(_cells(*row) for row in rows(before, after)),
        findings_html=findings_html,
        plan_rows="".join(_cells(f"{f.id} {f.title}", f.severity, f.remediation, f.script or "—", f.status)
                          for f in ordered),
    )


def _browser() -> str | None:
    for candidate in BROWSERS:
        found = candidate if Path(candidate).is_file() else shutil.which(candidate)
        if found:
            return found
    return None


def to_pdf(html_path: Path, pdf_path: Path) -> bool:
    browser = _browser()
    if browser is None:
        print("No Edge/Chromium found; open report/report.html and print it to PDF.", file=sys.stderr)
        return False
    subprocess.run(  # noqa: S603  # nosec B603 - fixed local browser, arguments are file paths
        [browser, "--headless=new", "--disable-gpu", "--no-pdf-header-footer",
         f"--print-to-pdf={pdf_path}", html_path.resolve().as_uri()],
        check=False, capture_output=True, timeout=120,
    )
    return pdf_path.is_file()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Generate the assessment report.")
    parser.add_argument("--pdf", action="store_true")
    args = parser.parse_args(argv)
    findings = load_findings(ROOT / "findings" / "findings.yaml")
    try:
        before_file, after_file = find_export(ROOT / "evidence" / "before"), find_export(ROOT / "evidence" / "after")
        before = parse_pingcastle(before_file) if before_file else None
        after = parse_pingcastle(after_file) if after_file else None
    except ScoresError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    out = ROOT / "report" / "report.html"
    out.write_bytes(render_html(findings, before, after, date.today()).encode("utf-8"))
    print(f"Wrote {out.relative_to(ROOT)}" + (" (draft)" if is_draft(findings, before, after) else ""))
    if args.pdf and to_pdf(out, out.with_suffix(".pdf")):
        print(f"Wrote {out.with_suffix('.pdf').relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
