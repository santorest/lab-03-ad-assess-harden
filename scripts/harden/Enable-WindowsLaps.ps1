#Requires -Version 5.1
<#
.SYNOPSIS
    Fixes W03: deploys Windows LAPS so every machine gets a unique, rotated local Administrator password in AD.
.DESCRIPTION
    1. Extends the AD schema for Windows LAPS (once).
    2. Lets computers in the Corp computer and Servers OUs write their own LAPS password.
    3. Lets only the Tier 2 admins read workstation passwords, and only the Tier 1 admins read server passwords.
    4. Creates and links the GPOs "LAB-Windows-LAPS" (workstations) and "LAB-Windows-LAPS-Servers": back up to
       AD, encrypted so only that tier's admin group can decrypt, 20 characters, 30-day rotation.
    Requires the Windows LAPS PowerShell module (Windows Server 2022 with the April 2023 update or later).
    Move app01 into OU=Servers and ws01, ws02 into the Corp computer OUs first (docs/build.md, step 4). Idempotent; -WhatIf aware.
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
# Windows LAPS reads group policy from this key; HKLM\Software\Microsoft\Policies\LAPS is the MDM (CSP) key.
$policyKey = 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS'
# One policy per tier: the encryption principal is a per-GPO setting, so workstations (Tier 2) and member
# servers (Tier 1) need separate GPOs for each tier to be the only one able to decrypt its machines' passwords.
$scopes = @(
    @{ Gpo = 'LAB-Windows-LAPS'; Admins = 'GG-Tier2-Admins'; Ous = @(foreach ($dept in 'Finance', 'Operations', 'Management') { "OU=Computers,OU=$dept,OU=Corp,$domainDn" }) }
    @{ Gpo = 'LAB-Windows-LAPS-Servers'; Admins = 'GG-Tier1-Admins'; Ous = @("OU=Servers,OU=Corp,$domainDn") }
)

$schemaDn = (Get-ADDomain).SubordinateReferences | Where-Object { $_ -like 'CN=Configuration,*' } | Select-Object -First 1
$schemaDn = if ($schemaDn) { "CN=Schema,$schemaDn" } else { "CN=Schema,CN=Configuration,$domainDn" }
if (-not (Get-ADObject -SearchBase $schemaDn -Filter "lDAPDisplayName -eq 'msLAPS-Password'")) {
    if ($PSCmdlet.ShouldProcess('AD schema', 'Add Windows LAPS attributes')) {
        Update-LapsADSchema -Confirm:$false
        Write-LabChange -Action 'UpdateLapsSchema' -Target $schemaDn
    }
}

foreach ($scope in $scopes) {
    foreach ($ou in $scope.Ous) {
        if ($PSCmdlet.ShouldProcess($ou, "Grant computers self-write and $($scope.Admins) read of LAPS passwords")) {
            # Both cmdlets set a fixed permission; re-applying them doesn't add duplicates.
            Set-LapsADComputerSelfPermission -Identity $ou | Out-Null
            Set-LapsADReadPasswordPermission -Identity $ou -AllowedPrincipals $scope.Admins | Out-Null
        }
    }

    # Read permission alone is not enough to see an encrypted password: only the encryption principal can
    # decrypt it (by default Domain Admins). Set it to the tier's admin group, by SID.
    $adminsSid = (Get-ADGroup -Identity $scope.Admins).SID.Value
    $settings = @(
        @{ ValueName = 'BackupDirectory'; Value = 2 }                # Active Directory
        @{ ValueName = 'ADPasswordEncryptionEnabled'; Value = 1 }
        @{ ValueName = 'ADPasswordEncryptionPrincipal'; Value = $adminsSid; Type = 'String' }
        @{ ValueName = 'PasswordComplexity'; Value = 4 }             # upper, lower, numbers, specials
        @{ ValueName = 'PasswordLength'; Value = 20 }
        @{ ValueName = 'PasswordAgeDays'; Value = 30 }
    ) | ForEach-Object { $_.Key = $policyKey; $_ }
    Set-LabGpoRegistryPolicy -GpoName $scope.Gpo -Comment "Windows LAPS for $($scope.Admins) - Lab 03 (W03)" -Settings $settings `
        -LinkTargets $scope.Ous -WhatIf:$WhatIfPreference
}
