#Requires -Version 5.1
<#
.SYNOPSIS
    Addresses W08: lists enabled user and computer accounts inactive for more than -Days (default 90).
.DESCRIPTION
    Report only by default. With -Disable, disables the listed accounts (-WhatIf shows what would happen).
    Accounts that never logged on are measured from their creation date. Built-in accounts are skipped.
    Refuses to run outside corp.internal unless -Force.
.EXAMPLE
    .\Get-StaleAccounts.ps1 | Format-Table
    .\Get-StaleAccounts.ps1 -Disable -WhatIf
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateRange(30, 3650)][int]$Days = 90,
    [switch]$Disable,
    [switch]$Force
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# Load the shared module once; re-importing would reset it (and any test mocks attached to it).
if (-not (Get-Module LabCommon)) { Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'LabCommon.psm1') }
Import-LabAdModule
Assert-LabDomain -Force:$Force

$now = Get-Date
$skip = @('krbtgt', 'Guest', 'DefaultAccount', 'WDAGUtilityAccount')
$accounts = @(Get-ADUser -Filter 'Enabled -eq $true' -Properties LastLogonDate, whenCreated) +
@(Get-ADComputer -Filter 'Enabled -eq $true' -Properties LastLogonDate, whenCreated)

$stale = foreach ($a in $accounts) {
    if ($skip -contains $a.SamAccountName) { continue }
    $since = if ($a.LastLogonDate) { $a.LastLogonDate } else { $a.whenCreated }
    $inactive = [int]($now - $since).TotalDays
    if ($inactive -gt $Days) {
        [pscustomobject]@{
            Name           = $a.SamAccountName
            Type           = $a.ObjectClass
            LastLogonDate  = $a.LastLogonDate
            DaysInactive   = $inactive
        }
    }
}

foreach ($s in $stale) {
    if ($Disable -and $PSCmdlet.ShouldProcess($s.Name, 'Disable stale account')) {
        Disable-ADAccount -Identity $s.Name
        Write-LabChange -Action 'DisableAccount' -Target $s.Name -Detail "$($s.DaysInactive) days inactive"
    }
    $s
}
