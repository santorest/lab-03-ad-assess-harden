# Building the lab domain

Isolated lab only (Lab 02's network). Windows evaluation licences are enough.

| Host | OS | Zone / IP | Role |
|---|---|---|---|
| dc01 | Windows Server 2022 | SERVERS · 10.10.20.11 | Domain controller and DNS for `corp.internal` |
| app01 | Windows Server 2022 | SERVERS · 10.10.20.13 | File and application server (member) |
| ws01 | Windows 11 | USERS · 10.10.30.21 | Workstation (member) |
| ws02 | Windows 11 | USERS · 10.10.30.22 | Workstation (member) |

## Steps
1. **Promote dc01** (Server Manager ▸ Add Roles ▸ Active Directory Domain Services ▸ *Promote this server*):
   new forest, root domain `corp.internal`, forest/domain functional level Windows Server 2016 or later.
2. **DNS forwarder** on dc01: the firewall (10.10.20.1), see Lab 02 guide 05.
3. **Join app01, ws01 and ws02** to `corp.internal` (Settings ▸ System ▸ About ▸ *Domain or workgroup*).
4. **Create the structure** on dc01, in an elevated Windows PowerShell:

   ```powershell
   Set-ExecutionPolicy -Scope Process Bypass
   .\scripts\build\New-LabDomainStructure.ps1 -WhatIf   # review what it will do
   .\scripts\build\New-LabDomainStructure.ps1
   ```

   It creates the `Corp` and `Admin` OU trees, department groups, `GG-Helpdesk` and 40 fictional users. Users
   get a random password nobody knows and must change it at first logon: reset the password of the few accounts
   you use (`Set-ADAccountPassword -Reset`). Every change is logged to `logs/changes.log`.
5. **Snapshot all four VMs** — this is the clean baseline you can return to.
6. Apply the weaknesses in [weaknesses.md](weaknesses.md), then snapshot again: that is the "before" state.
