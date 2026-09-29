#Requires -Version 5.1
<#
.SYNOPSIS
    Fixes W03: deploys Windows LAPS so every machine gets a unique, rotated local Administrator password in AD.
.DESCRIPTION
    1. Extends the AD schema for Windows LAPS (once).
    2. Lets computers in the Corp computer OUs write their own LAPS password.
    3. Lets only the Tier 2 admins read workstation passwords.
    4. Creates and links the GPO "LAB-Windows-LAPS": back up to AD, encrypted so only GG-Tier2-Admins can
       decrypt, 20 characters, 30-day rotation.
    Requires the Windows LAPS PowerShell module (Windows Server 2022 with the April 2023 update or later).
    Move app01, ws01 and ws02 into the Corp computer OUs first (docs/build.md). Idempotent; -WhatIf aware.
#>
[CmdletBinding(SupportsShouldProcess)]
param([switch]$Force)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# Load the shared module once; re-importing would reset it (and any test mocks attached to it).
if (-not (Get-Module LabCommon)) { Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'LabCommon.psm1') }
Import-LabAdModule
Assert-LabDomain -Force:$Force
$domainDn = (Get-ADDomain).DistinguishedName
$gpoName = 'LAB-Windows-LAPS'
# Windows LAPS reads group policy from this key; HKLM\Software\Microsoft\Policies\LAPS is the MDM (CSP) key.
$policyKey = 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS'
$computerOus = foreach ($dept in 'Finance', 'Operations', 'Management') { "OU=Computers,OU=$dept,OU=Corp,$domainDn" }

$schemaDn = (Get-ADDomain).SubordinateReferences | Where-Object { $_ -like 'CN=Configuration,*' } | Select-Object -First 1
$schemaDn = if ($schemaDn) { "CN=Schema,$schemaDn" } else { "CN=Schema,CN=Configuration,$domainDn" }
if (-not (Get-ADObject -SearchBase $schemaDn -Filter "lDAPDisplayName -eq 'msLAPS-Password'")) {
    if ($PSCmdlet.ShouldProcess('AD schema', 'Add Windows LAPS attributes')) {
        Update-LapsADSchema -Confirm:$false
        Write-LabChange -Action 'UpdateLapsSchema' -Target $schemaDn
    }
}

foreach ($ou in $computerOus) {
    if ($PSCmdlet.ShouldProcess($ou, 'Grant computers self-write and Tier 2 read of LAPS passwords')) {
        # Both cmdlets set a fixed permission; re-applying them doesn't add duplicates.
        Set-LapsADComputerSelfPermission -Identity $ou | Out-Null
        Set-LapsADReadPasswordPermission -Identity $ou -AllowedPrincipals 'GG-Tier2-Admins' | Out-Null
    }
}

# Read permission alone is not enough to see an encrypted password: only the encryption principal can
# decrypt it (by default Domain Admins). Set it to the Tier 2 group, by SID.
$tier2Sid = (Get-ADGroup -Identity 'GG-Tier2-Admins').SID.Value
$settings = @(
    @{ ValueName = 'BackupDirectory'; Value = 2 }                # Active Directory
    @{ ValueName = 'ADPasswordEncryptionEnabled'; Value = 1 }
    @{ ValueName = 'ADPasswordEncryptionPrincipal'; Value = $tier2Sid; Type = 'String' }
    @{ ValueName = 'PasswordComplexity'; Value = 4 }             # upper, lower, numbers, specials
    @{ ValueName = 'PasswordLength'; Value = 20 }
    @{ ValueName = 'PasswordAgeDays'; Value = 30 }
) | ForEach-Object { $_.Key = $policyKey; $_ }
Set-LabGpoRegistryPolicy -GpoName $gpoName -Comment 'Windows LAPS - Lab 03 (W03)' -Settings $settings `
    -LinkTargets $computerOus -WhatIf:$WhatIfPreference
