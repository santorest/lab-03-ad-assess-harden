# Evidence

Tool exports go here, in two folders: `before/` (baseline assessment) and `after/` (after hardening).
Everything in this folder except this file is git-ignored: exports contain user names, group memberships and
host names. Review and sanitize anything before committing it, and never commit password material.

| Tool | Files | Folder |
|---|---|---|
| PingCastle | `ad_hc_corp.internal.xml`, `.html` | `before/`, `after/` |
| BloodHound CE | exported findings / screenshots | `before/`, `after/` |
| Policy Analyzer | comparison export | `before/`, `after/` |
