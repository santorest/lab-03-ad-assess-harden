# Assessment 1: PingCastle health check

PingCastle produces a risk score (lower is better) and a list of rules that matched, grouped into stale objects,
privileged accounts, trusts and anomalies. It only reads from AD.

1. On **ws01**, logged on as a normal domain user, download PingCastle (free "Basic" edition) from
   <https://www.pingcastle.com/download/> and record the version in the test plan.
2. Run `PingCastle.exe --healthcheck --server corp.internal`.
3. It writes `ad_hc_corp.internal.html` and `ad_hc_corp.internal.xml`. Copy both to `evidence/before/` (or
   `evidence/after/` after hardening), renaming them with the date, e.g. `ad_hc_corp.internal_20261001.xml`.
4. Generate the score table: `python -m adlab.scores`.
5. For each finding in [../../findings/findings.yaml](../../findings/findings.yaml), replace the *Expected*
   evidence with the PingCastle rule that actually matched (rule ID and title).

Keep the HTML report local: it lists user and group names. Screenshots for the write-up must be sanitized.
