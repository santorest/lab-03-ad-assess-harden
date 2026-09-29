#Requires -Version 5.1
<#
.SYNOPSIS
    Fixes W06: domain controllers require LDAP signing and always enforce LDAP channel binding.
.DESCRIPTION
    Creates and links the GPO "LAB-LDAP-Signing" first on the Domain Controllers OU:
    LDAPServerIntegrity = 2 (require signing) and LdapEnforceChannelBinding = 2 (always).
    Before applying in a real network, check the DCs' Directory Service log for events 2889 (clients binding
    without signing). Idempotent and -WhatIf aware. Refuses to run outside corp.internal unless -Force.
#>
[CmdletBinding(SupportsShouldProcess)]
param([switch]$Force)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# Load the shared module once; re-importing would reset it (and any test mocks attached to it).
if (-not (Get-Module LabCommon)) { Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'LabCommon.psm1') }
Import-LabAdModule
Assert-LabDomain -Force:$Force

# Security options, written like the Default Domain Controllers Policy writes them (it sets LDAPServerIntegrity
# to 1, "None"): in the GPO security template, linked first on the Domain Controllers OU so this GPO wins.
$securityOptions = [ordered]@{
    'Registry Values' = [ordered]@{
        'MACHINE\System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity'       = '4,2'  # require signing
        'MACHINE\System\CurrentControlSet\Services\NTDS\Parameters\LdapEnforceChannelBinding' = '4,2'  # always
    }
}
Set-LabGpoRegistryPolicy -GpoName 'LAB-LDAP-Signing' -Comment 'LDAP signing and channel binding on DCs - Lab 03 (W06)' `
    -SecurityTemplate $securityOptions -LinkFirst -WhatIf:$WhatIfPreference `
    -LinkTargets @("OU=Domain Controllers,$((Get-ADDomain).DistinguishedName)")
