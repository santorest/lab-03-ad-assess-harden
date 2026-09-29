#Requires -Version 5.1
<#
.SYNOPSIS
    Shared helpers for the Lab 03 scripts: domain guard and change log.
.DESCRIPTION
    Every build and hardening script imports this module. Assert-LabDomain refuses to run against any domain
    other than the lab domain (corp.internal) unless -Force is given, so a script copied to a real environment
    cannot change it by accident. Write-LabChange records every change the scripts make.
#>
Set-StrictMode -Version Latest

$script:LabDomain = 'corp.internal'

function Get-LabDomainName {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    $script:LabDomain
}

function Assert-LabDomain {
    [CmdletBinding()]
    param(
        # Allow running against a domain that is not corp.internal.
        [switch]$Force
    )
    $current = [string](Get-ADDomain -ErrorAction Stop).DNSRoot
    if ($current -ne $script:LabDomain) {
        if ($Force) {
            Write-Warning "Running against '$current' instead of the lab domain '$script:LabDomain' (-Force)."
            return
        }
        throw "This script only runs against the lab domain '$script:LabDomain' (current domain: '$current'). Use -Force to override."
    }
}

function Write-LabChange {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Action,
        [Parameter(Mandatory)][string]$Target,
        [string]$Detail = ''
    )
    $line = '{0} {1} {2} {3}' -f (Get-Date).ToString('s'), $Action, $Target, $Detail
    $logDir = Join-Path (Split-Path $PSScriptRoot -Parent) 'logs'
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
    Add-Content -Path (Join-Path $logDir 'changes.log') -Value $line.TrimEnd()
    Write-Verbose $line
}

function Import-LabAdModule {
    [CmdletBinding()]
    param()
    # Tests define stand-in AD commands; on a real server load the RSAT ActiveDirectory module.
    if (-not (Get-Command Get-ADDomain -ErrorAction SilentlyContinue)) {
        Import-Module ActiveDirectory -ErrorAction Stop
    }
}

Export-ModuleMember -Function Get-LabDomainName, Assert-LabDomain, Write-LabChange, Import-LabAdModule
