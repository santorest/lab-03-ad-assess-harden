#Requires -Version 5.1
<#
.SYNOPSIS
    Imports Microsoft's Windows Server 2022 security baseline GPOs and links the domain-controller baseline.
.DESCRIPTION
    -BaselinePath is the extracted "Windows Server 2022 Security Baseline" folder from the Microsoft Security
    Compliance Toolkit (it contains GPOs\manifest.xml). Imports the Domain Controller and Member Server baseline
    GPOs under their Microsoft names, links the Domain Controller one to the Domain Controllers OU and, with
    -MemberServerOu, the Member Server one to that OU. Existing GPOs and links are left alone.
    Review the baseline in a test OU first in a real network. Refuses to run outside corp.internal unless -Force.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$BaselinePath,
    [string]$MemberServerOu,
    [switch]$Force
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'LabCommon.psm1') -Force
Import-LabAdModule
Assert-LabDomain -Force:$Force
$domainDn = (Get-ADDomain).DistinguishedName

$gpoFolder = Join-Path $BaselinePath 'GPOs'
$manifest = Join-Path $gpoFolder 'manifest.xml'
if (-not (Test-Path $manifest)) {
    throw "No GPO backups found: expected $manifest (extract the Windows Server 2022 Security Baseline first)."
}
[xml]$xml = Get-Content -Path $manifest -Raw
$backups = @($xml.Backups.BackupInst)

$wanted = @(
    @{ Match = '*Domain Controller'; Link = "OU=Domain Controllers,$domainDn" },
    @{ Match = '*Member Server'; Link = $MemberServerOu }
)
foreach ($w in $wanted) {
    $backup = $backups | Where-Object { $_.GPODisplayName.'#cdata-section' -like $w.Match } | Select-Object -First 1
    if (-not $backup) { Write-Warning "Baseline GPO matching '$($w.Match)' not found in the manifest."; continue }
    $name = $backup.GPODisplayName.'#cdata-section'
    $id = $backup.ID.'#cdata-section' -replace '[{}]', ''
    if (-not (Get-GPO -Name $name -ErrorAction SilentlyContinue)) {
        if ($PSCmdlet.ShouldProcess($name, 'Import baseline GPO')) {
            Import-GPO -BackupId $id -TargetName $name -Path $gpoFolder -CreateIfNeeded | Out-Null
            Write-LabChange -Action 'ImportBaseline' -Target $name
        }
    }
    if ($w.Link) {
        $linked = @((Get-GPInheritance -Target $w.Link).GpoLinks | Where-Object { $_.DisplayName -eq $name })
        if (-not $linked -and $PSCmdlet.ShouldProcess($w.Link, "Link $name")) {
            New-GPLink -Name $name -Target $w.Link | Out-Null
            Write-LabChange -Action 'LinkGpo' -Target $w.Link -Detail $name
        }
    }
}
