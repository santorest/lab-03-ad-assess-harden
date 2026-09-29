# Test plan

## Assessment
| # | Step | Guide | Result | Evidence |
|---|---|---|---|---|
| A1 | PingCastle before-scan, score recorded | docs/assessment/01-pingcastle.md | | evidence/before/ |
| A2 | BloodHound paths to Domain Admins recorded (expect W01, W07, W09) | docs/assessment/02-bloodhound.md | | evidence/before/ |
| A3 | Policy Analyzer gaps vs WS2022 baseline recorded | docs/assessment/03-policy-analyzer.md | | evidence/before/ |
| A4 | Every hardening script reviewed with -WhatIf, then applied | scripts/harden/ | | logs/changes.log |
| A5 | Each script run a second time makes no change | scripts/harden/ | | logs/changes.log |
| A6 | PingCastle after-scan, score lower | docs/assessment/01-pingcastle.md | | evidence/after/ |
| A7 | BloodHound: no path to Domain Admins from W01/W07/W09 | docs/assessment/02-bloodhound.md | | evidence/after/ |
| A8 | `gpresult /r` on ws01 shows LAB-Tier0-Logon-Restrictions; a Domain Admin can't log on | Set-TieredAdminModel.ps1 | | screenshot |
| A9 | GPO versions consistent: `Get-GPO LAB-Tier0-Logon-Restrictions` shows equal DS and SysVol computer versions; `GPT.INI` is at the GPO root | Set-TieredAdminModel.ps1 | | screenshot |
| A10 | After `gpupdate /force` on dc01, `Get-ADDefaultDomainPasswordPolicy` shows length 14, lockout 10 / 15 min | Set-PasswordPolicy.ps1 | | screenshot |
| A11 | On ws01, `reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS` lists the six LAPS settings | Enable-WindowsLaps.ps1 | | screenshot |
| A12 | `Get-LapsADPassword ws01 -AsPlainText` works for a Tier 2 admin and fails for a Tier 1 admin; for app01 the reverse | Enable-WindowsLaps.ps1 | | screenshot |
| A13 | `gpresult /h` on dc01 shows LAB-LDAP-Signing and LAB-Legacy-Protocols as the winning GPO for *LDAP server signing requirements* and *LAN Manager authentication level*; `reg query` shows LDAPServerIntegrity = 2 on dc01 and LmCompatibilityLevel = 5 on dc01 and ws01 | Set-LdapSigning.ps1, Disable-LegacyProtocols.ps1 | | screenshot |

## SIEM (docs/siem-checks.md)
| # | Check | Result | Evidence |
|---|---|---|---|
| S1 | 4728 group change alert | | |
| S2 | 4732 group change alert | | |
| S3 | 4756 group change alert | | |
| S4 | 4625 failed logons | | |
| S5 | 4740 lockout | | |
| S6 | 4662 LAPS password read visible | | |
| S7 | 5136 directory changes from the scripts | | |
