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

function Set-LabGpoRegistryPolicy {
    <#
    .SYNOPSIS
        Ensures a GPO exists, carries the given DWORD registry settings and is linked to the given targets.
        Only missing or different values are written; existing links are kept. Returns nothing.
        Callers must pass -WhatIf:$WhatIfPreference: preference variables don't flow into module functions.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$GpoName,
        [Parameter(Mandatory)][string]$Comment,
        # Each item: @{ Key = 'HKLM\...'; ValueName = '...'; Value = <int> }
        [Parameter(Mandatory)][hashtable[]]$Settings,
        [Parameter(Mandatory)][string[]]$LinkTargets
    )
    $gpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
    if (-not $gpo -and $PSCmdlet.ShouldProcess($GpoName, 'Create GPO')) {
        $gpo = New-GPO -Name $GpoName -Comment $Comment
        Write-LabChange -Action 'CreateGpo' -Target $GpoName
    }
    if (-not $gpo) { return }
    foreach ($s in $Settings) {
        $current = Get-GPRegistryValue -Name $GpoName -Key $s.Key -ValueName $s.ValueName -ErrorAction SilentlyContinue
        if (-not $current -or $current.Value -ne $s.Value) {
            if ($PSCmdlet.ShouldProcess("$GpoName $($s.ValueName)", "Set to $($s.Value)")) {
                Set-GPRegistryValue -Name $GpoName -Key $s.Key -ValueName $s.ValueName -Type DWord -Value $s.Value | Out-Null
                Write-LabChange -Action 'SetGpoValue' -Target $GpoName -Detail "$($s.ValueName)=$($s.Value)"
            }
        }
    }
    foreach ($target in $LinkTargets) {
        $linked = @((Get-GPInheritance -Target $target).GpoLinks | Where-Object { $_.DisplayName -eq $GpoName })
        if (-not $linked -and $PSCmdlet.ShouldProcess($target, "Link $GpoName")) {
            New-GPLink -Name $GpoName -Target $target | Out-Null
            Write-LabChange -Action 'LinkGpo' -Target $target -Detail $GpoName
        }
    }
}

Export-ModuleMember -Function Get-LabDomainName, Assert-LabDomain, Write-LabChange, Import-LabAdModule, Set-LabGpoRegistryPolicy
