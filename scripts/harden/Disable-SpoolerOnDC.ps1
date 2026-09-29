#Requires -Version 5.1
<#
.SYNOPSIS
    Fixes W11: stops and disables the Print Spooler on a domain controller.
.DESCRIPTION
    Run it on each domain controller (it acts on the local machine and refuses to run on a non-DC).
    Domain controllers should not print; the Spooler service has a long history of critical vulnerabilities.
    Idempotent and -WhatIf aware. Refuses to run outside corp.internal unless -Force.
#>
[CmdletBinding(SupportsShouldProcess)]
param([switch]$Force)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'LabCommon.psm1') -Force
Import-LabAdModule
Assert-LabDomain -Force:$Force

# DomainRole 4 = backup DC, 5 = primary DC
$role = (Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole
if ($role -lt 4 -and -not $Force) {
    throw 'This machine is not a domain controller. Run the script on each DC (or use -Force).'
}

$spooler = Get-Service -Name Spooler
if ($spooler.Status -ne 'Stopped' -and $PSCmdlet.ShouldProcess('Spooler', 'Stop service')) {
    Stop-Service -Name Spooler -Force
    Write-LabChange -Action 'StopService' -Target "$env:COMPUTERNAME Spooler"
}
if ($spooler.StartType -ne 'Disabled' -and $PSCmdlet.ShouldProcess('Spooler', 'Disable service')) {
    Set-Service -Name Spooler -StartupType Disabled
    Write-LabChange -Action 'DisableService' -Target "$env:COMPUTERNAME Spooler"
}
