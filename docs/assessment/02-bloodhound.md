# Assessment 2: BloodHound Community Edition

BloodHound maps relationships in AD (group memberships, delegated rights, logon sessions) and shows which ones
lead to privileged groups. Defenders use it to find and remove those relationships.

1. On the analyst machine (the MGMT jump host, not a domain controller), install BloodHound CE with its official
   Docker Compose file from <https://github.com/SpecterOps/BloodHound> and record the version.
2. Download the matching **SharpHound** collector from the BloodHound CE UI (*Download Collectors*).
3. On **ws01**, as a normal domain user, run the collector with the default collection methods; it produces a
   ZIP of JSON files. Copy the ZIP to the analyst machine and upload it in the BloodHound UI.
4. Review, and export screenshots or tables to `evidence/before/`:
    - *Shortest paths to Domain Admins* — expect the service account (W01) and admin sessions on workstations
      (W09) to appear.
    - *Outbound object control* of `GG-Helpdesk` — expect the helpdesk delegation (W07):
      `ForceChangePassword` on `adm.app`, which is `AdminTo` app01.
    - Members of *Domain Admins* and which computers they have sessions on.
5. Record each relevant path as evidence in the findings register.
6. After hardening, repeat the collection into `evidence/after/`: the paths should be gone.

Delete the collection ZIP from ws01 after uploading it; it is a map of the domain.
