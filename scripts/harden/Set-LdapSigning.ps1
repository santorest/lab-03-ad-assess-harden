#Requires -Version 5.1
<#
.SYNOPSIS
    Fixes W06: domain controllers require LDAP signing and always enforce LDAP channel binding.
.DESCRIPTION
    Creates and links the GPO "LAB-LDAP-Signing" to the Domain Controllers OU:
    LDAPServerIntegrity = 2 (require signing) and LdapEnforceChannelBinding = 2 (always).
    Before applying in a real network, check the DCs' Directory Service log for events 2889 (clients binding
    without signing). Idempotent and -WhatIf aware. Refuses to run outside corp.internal unless -Force.
#>
[CmdletBinding(SupportsShouldProcess)]
param([switch]$Force)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'LabCommon.psm1') -Force
Import-LabAdModule
Assert-LabDomain -Force:$Force

$ntds = 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
$settings = @(
    @{ Key = $ntds; ValueName = 'LDAPServerIntegrity'; Value = 2 },
    @{ Key = $ntds; ValueName = 'LdapEnforceChannelBinding'; Value = 2 }
)
Set-LabGpoRegistryPolicy -GpoName 'LAB-LDAP-Signing' -Comment 'LDAP signing and channel binding on DCs - Lab 03 (W06)' `
    -Settings $settings -WhatIf:$WhatIfPreference -LinkTargets @("OU=Domain Controllers,$((Get-ADDomain).DistinguishedName)")
