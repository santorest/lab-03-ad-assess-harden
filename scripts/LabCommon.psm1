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

function Merge-LabInfTemplate {
    <#
    .SYNOPSIS
        Merges settings into a security template (GptTmpl.inf) text and returns the new text.
        Existing sections and keys are kept; only the given keys are added or overridden.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowEmptyString()][AllowNull()][string]$Current,
        # @{ 'Section Name' = @{ Key = 'Value' } }; use ordered dictionaries to keep a stable layout.
        [Parameter(Mandatory)][System.Collections.IDictionary]$Sections
    )
    $parsed = [ordered]@{
        'Unicode' = [ordered]@{ 'Unicode' = 'yes' }
        'Version' = [ordered]@{ 'signature' = '"$CHICAGO$"'; 'Revision' = '1' }
    }
    $section = $null
    foreach ($line in ($Current -split '\r?\n')) {
        $text = $line.Trim()
        if ($text -match '^\[(.+)\]$') {
            $section = $Matches[1]
            if (-not $parsed.Contains($section)) { $parsed[$section] = [ordered]@{} }
        } elseif ($section -and $text -match '^([^=;]+?)\s*=\s*(.*)$') {
            $parsed[$section][$Matches[1]] = $Matches[2]
        }
    }
    foreach ($name in $Sections.Keys) {
        if (-not $parsed.Contains($name)) { $parsed[$name] = [ordered]@{} }
        foreach ($key in $Sections[$name].Keys) { $parsed[$name][$key] = [string]$Sections[$name][$key] }
    }
    $out = foreach ($name in $parsed.Keys) {
        "[$name]"
        # The header sections keep the compact form secedit writes; settings use 'Key = Value'.
        $separator = if ($name -in 'Unicode', 'Version') { '=' } else { ' = ' }
        foreach ($key in $parsed[$name].Keys) { "$key$separator$($parsed[$name][$key])" }
    }
    $out -join "`r`n"
}

function Merge-LabGpoExtensionList {
    <#
    .SYNOPSIS
        Merges client-side extension pairs into a gPCMachineExtensionNames value, without duplicates.
        Group Policy expects the list sorted by extension GUID, and each extension's tool GUIDs sorted too.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowEmptyString()][AllowNull()][string]$Current,
        [Parameter(Mandatory)][string]$Add
    )
    $map = @{}
    foreach ($value in $Current, $Add) {
        foreach ($block in [regex]::Matches([string]$value, '\[([^\]]+)\]')) {
            $guids = @([regex]::Matches($block.Groups[1].Value, '\{[0-9A-Fa-f-]{36}\}') | ForEach-Object { $_.Value.ToUpperInvariant() })
            if (-not $guids) { continue }
            $cse = $guids[0]
            if (-not $map.ContainsKey($cse)) { $map[$cse] = New-Object System.Collections.Generic.List[string] }
            foreach ($tool in ($guids | Select-Object -Skip 1)) { if (-not $map[$cse].Contains($tool)) { $map[$cse].Add($tool) } }
        }
    }
    ($map.Keys | Sort-Object | ForEach-Object { '[' + $_ + (($map[$_] | Sort-Object) -join '') + ']' }) -join ''
}

function Set-LabGpoSecurityTemplate {
    <#
    .SYNOPSIS
        Merges settings into a GPO's security template (Machine\...\SecEdit\GptTmpl.inf) in SYSVOL.
    .DESCRIPTION
        Writes only when a setting is missing or different. On a change it bumps the GPO version both in AD
        and in GPT.INI at the GPO root (so clients re-apply it), and merges the security extension into
        gPCMachineExtensionNames instead of replacing what the GPO already carries.
        Callers must pass -WhatIf:$WhatIfPreference: preference variables don't flow into module functions.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][guid]$GpoId,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Sections,
        # Folder holding the {GUID} policy folders; defaults to the domain's SYSVOL Policies share.
        [string]$PolicyRoot
    )
    $domain = Get-ADDomain
    if (-not $PolicyRoot) { $PolicyRoot = "\\$($domain.DNSRoot)\SYSVOL\$($domain.DNSRoot)\Policies" }
    $gpoDir = Join-Path $PolicyRoot "{$GpoId}"
    $secEdit = Join-Path $gpoDir 'Machine\Microsoft\Windows NT\SecEdit'
    $infPath = Join-Path $secEdit 'GptTmpl.inf'
    $current = if (Test-Path -LiteralPath $infPath) { Get-Content -LiteralPath $infPath -Raw -Encoding Unicode } else { '' }
    $merged = Merge-LabInfTemplate -Current $current -Sections $Sections
    if ($merged.Trim() -eq ([string]$current).Trim()) { return }
    if (-not $PSCmdlet.ShouldProcess("GPO {$GpoId}", 'Write security template settings')) { return }

    New-Item -ItemType Directory -Path $secEdit -Force | Out-Null
    Set-Content -LiteralPath $infPath -Value $merged -Encoding Unicode
    $securityCse = '[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]'
    $gpoDn = "CN={$GpoId},CN=Policies,CN=System,$($domain.DistinguishedName)"
    $obj = Get-ADObject -Identity $gpoDn -Properties versionNumber, gPCMachineExtensionNames
    $version = [int]$obj.versionNumber + 1
    $extensions = Merge-LabGpoExtensionList -Current $obj.gPCMachineExtensionNames -Add $securityCse
    Set-ADObject -Identity $gpoDn -Replace @{ gPCMachineExtensionNames = $extensions; versionNumber = $version }
    # GPT.INI sits at the GPO root; keep its other lines (displayName) and update only Version.
    $gptIni = Join-Path $gpoDir 'GPT.INI'
    $lines = if (Test-Path -LiteralPath $gptIni) { @(Get-Content -LiteralPath $gptIni | Where-Object { $_ -notmatch '^\s*Version\s*=' }) } else { @('[General]') }
    Set-Content -LiteralPath $gptIni -Value (@($lines) + "Version=$version") -Encoding Ascii
    Write-LabChange -Action 'SetSecurityTemplate' -Target "{$GpoId}" -Detail (@($Sections.Keys) -join ', ')
}

Export-ModuleMember -Function Get-LabDomainName, Assert-LabDomain, Write-LabChange, Import-LabAdModule, Set-LabGpoRegistryPolicy,
    Merge-LabInfTemplate, Merge-LabGpoExtensionList, Set-LabGpoSecurityTemplate
