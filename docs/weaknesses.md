# Baseline weaknesses

These are configuration weaknesses commonly found in small and mid-sized Active Directory environments. Apply
them **only in the isolated lab**, after the clean-baseline snapshot ([build.md](build.md)), so the assessment
tools have realistic findings to report. Each maps to a finding in
[../findings/findings.yaml](../findings/findings.yaml) and to the script that fixes it.

| ID | Weakness | Why it is common in SMBs | How to set it in the lab | Should be flagged by |
|---|---|---|---|---|
| W01 | A service account is a member of Domain Admins | "It didn't work until we gave it admin" during an app install | Create `svc-app` in `Corp/ServiceAccounts` and add it to *Domain Admins* (ADUC ▸ Member Of) | PingCastle, BloodHound |
| W02 | Service account password never expires | Nobody knows what breaks if it changes | On `svc-app`: *Account* tab ▸ tick *Password never expires* | PingCastle |
| W03 | Same local Administrator password everywhere (no LAPS) | Machines were built from one image with one password | Set the same local Administrator password on app01, ws01, ws02; don't deploy LAPS | PingCastle, Policy Analyzer |
| W04 | SMBv1 enabled on the file server | Kept "for an old scanner" | On app01: `Set-SmbServerConfiguration -EnableSMB1Protocol $true` (after enabling the SMB1 feature) | PingCastle |
| W05 | NTLMv1 / LM allowed | Default on old domains, never revisited | Default Domain Policy ▸ *Network security: LAN Manager authentication level* = *Send LM & NTLM responses* | PingCastle, Policy Analyzer |
| W06 | LDAP signing and channel binding not required | Defaults on older builds; fear of breaking apps | Leave *Domain controller: LDAP server signing requirements* = *None* on dc01 | PingCastle |
| W07 | Helpdesk can reset administrator passwords | Delegation granted on the Admin OU instead of user OUs | Create `adm.app` in `Admin/Tier1` (not in any built-in admin group) and add it to the local *Administrators* of app01; then delegate *Reset user passwords* to `GG-Helpdesk` on the **Admin** OU (Delegation of Control wizard) — see the note below | BloodHound |
| W08 | Stale enabled accounts | Leavers disabled late or never | Keep 3 users enabled that you never log on with; PingCastle ages them once the lab runs long enough | PingCastle |
| W09 | Domain Admins log on to workstations | One admin account for everything | Log on to ws01 and ws02 interactively with a Domain Admins member | BloodHound (sessions) |
| W10 | Weak password and lockout policy | Complaints about password rules | Default Domain Policy: minimum length 7, account lockout threshold 0 | PingCastle, Policy Analyzer |
| W11 | Print Spooler running on the domain controller | Enabled by default, rarely reviewed | Leave the *Print Spooler* service running on dc01 (default) | PingCastle |

After applying them, take the **"before" snapshot** and run the assessment ([assessment/](assessment/)).

**Why W07 uses a Tier 1 admin, not a Domain Admin.** Members of protected groups (Domain Admins and the other
built-in admin groups) get their permissions reset every hour from *AdminSDHolder*, which turns off inheritance:
a delegation on the Admin OU never reaches them. Unprotected admin accounts, such as a server admin, do inherit
it, and they are the ones a misplaced helpdesk delegation exposes in real domains. BloodHound then shows
`GG-Helpdesk → ForceChangePassword → adm.app → AdminTo → app01`.
