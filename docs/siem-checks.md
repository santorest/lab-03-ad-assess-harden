# SIEM checks (Lab 01 Wazuh)

The hardening should not only close weaknesses but also leave the important changes visible. With the Wazuh
agent on dc01 ([Lab 01](https://github.com/santorest/lab-01-wazuh-siem)) and the Windows audit policy from
Lab 01 applied, confirm each event reaches Wazuh:

| # | Action in the lab | Windows event | Expected in Wazuh |
|---|---|---|---|
| S1 | Add a user to *Domain Admins* | 4728 (member added to a global security group) | Alert naming the group and the account |
| S2 | Add a user to a domain-local admin group | 4732 | Alert |
| S3 | Add a user to a universal group | 4756 | Alert |
| S4 | Five failed logons for one account on ws01 | 4625 | Authentication-failure alerts |
| S5 | Exceed the new lockout threshold | 4740 (account locked out) | Lockout alert |
| S6 | Read a computer's LAPS password | 4662 on the computer object, for the LAPS password attribute (needs *Audit Directory Service Access* and a SACL on the Computers OU) | Event visible; add a custom rule if Wazuh doesn't alert on it |
| S7 | Run a hardening script | Changes appear as 5136 (directory object modified) for OU/GPO edits | Event visible |

Record the result of each check in [../tests/test-plan.md](../tests/test-plan.md).
