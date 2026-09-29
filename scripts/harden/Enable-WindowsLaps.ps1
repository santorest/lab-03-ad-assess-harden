#Requires -Version 5.1
<#
.SYNOPSIS
    Fixes W03: deploys Windows LAPS so every machine gets a unique, rotated local Administrator password in AD.
.DESCRIPTION
    1. Extends the AD schema for Windows LAPS (once).
    2. Lets computers in the Corp computer OUs write their own LAPS password.
    3. Lets only the Tier 2 admins read workstation passwords.
    4. Creates and links the GPO "LAB-Windows-LAPS": back up to AD, encrypted, 20 characters, 30-day rotation.
    Requires the Windows LAPS PowerShell module (Windows Server 2022 with the April 2023 update or later).
    Move app01, ws01 and ws02 into the Corp computer OUs first (docs/build.md). Idempotent; -WhatIf aware.
#>
[CmdletBinding(SupportsShouldProcess)]
param([switch]$Force)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'LabCommon.psm1') -Force
Import-LabAdModule
Assert-LabDomain -Force:$Force
$domainDn = (Get-ADDomain).DistinguishedName
$gpoName = 'LAB-Windows-LAPS'
$policyKey = 'HKLM\Software\Microsoft\Policies\LAPS'
$settings = [ordered]@{
    BackupDirectory             = 2   # Active Directory
    ADPasswordEncryptionEnabled = 1
    PasswordComplexity          = 4   # upper, lower, numbers, specials
    PasswordLength              = 20
    PasswordAgeDays             = 30
}
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

$gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
if (-not $gpo -and $PSCmdlet.ShouldProcess($gpoName, 'Create GPO')) {
    $gpo = New-GPO -Name $gpoName -Comment 'Windows LAPS - Lab 03 (W03)'
    Write-LabChange -Action 'CreateGpo' -Target $gpoName
}
if ($gpo) {
    foreach ($name in $settings.Keys) {
        $current = Get-GPRegistryValue -Name $gpoName -Key $policyKey -ValueName $name -ErrorAction SilentlyContinue
        if (-not $current -or $current.Value -ne $settings[$name]) {
            if ($PSCmdlet.ShouldProcess("$gpoName $name", "Set to $($settings[$name])")) {
                Set-GPRegistryValue -Name $gpoName -Key $policyKey -ValueName $name -Type DWord -Value $settings[$name] | Out-Null
                Write-LabChange -Action 'SetGpoValue' -Target $gpoName -Detail "$name=$($settings[$name])"
            }
        }
    }
    foreach ($ou in $computerOus) {
        $linked = @((Get-GPInheritance -Target $ou).GpoLinks | Where-Object { $_.DisplayName -eq $gpoName })
        if (-not $linked -and $PSCmdlet.ShouldProcess($ou, "Link $gpoName")) {
            New-GPLink -Name $gpoName -Target $ou | Out-Null
            Write-LabChange -Action 'LinkGpo' -Target $ou -Detail $gpoName
        }
    }
}
