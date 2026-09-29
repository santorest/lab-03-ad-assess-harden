# Assessment 3: Microsoft security baseline comparison

Microsoft's Security Compliance Toolkit includes the **Windows Server 2022 security baseline** (as GPO backups)
and **Policy Analyzer**, which compares baselines with the policies actually applied.

1. Download the Security Compliance Toolkit from Microsoft (search "Microsoft Security Compliance Toolkit 1.0")
   and extract *Windows Server 2022 Security Baseline* and *PolicyAnalyzer*. Record the baseline version.
2. On dc01, export the effective policy: `gpresult /h evidence\before\gpresult-dc01.html` and, in Policy Analyzer,
   *Add ▸ File ▸ Import from local policy* (or add the domain GPO backups with *Add ▸ Import GPO(s)*).
3. Compare the baseline's *Domain Controller* and *Member Server* policy sets with the current ones and export
   the differences (*View/Compare ▸ Export to Excel*) to `evidence/before/`.
4. Findings to look for: LAN Manager authentication level (W05), LDAP signing (W06), password policy (W10),
   and the absence of LAPS settings (W03).
5. `scripts/harden/Import-SecurityBaseline.ps1` later imports the same baseline GPOs; re-run the comparison into
   `evidence/after/` to show the gap closed.
