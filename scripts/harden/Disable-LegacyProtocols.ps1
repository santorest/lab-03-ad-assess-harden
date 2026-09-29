#Requires -Version 5.1
<#
.SYNOPSIS
    Fixes W04/W05: disables SMBv1, requires SMB signing and allows only NTLMv2 (LmCompatibilityLevel 5).
.DESCRIPTION
    Creates and links the GPO "LAB-Legacy-Protocols" at the domain root, so it applies to domain controllers,
    servers and workstations. Test application first: an old device that only speaks SMBv1 or NTLMv1 stops
    working, which is the point, but find it before users do (PingCastle and the event logs list them).
    Idempotent and -WhatIf aware. Refuses to run outside corp.internal unless -Force.
#>
[CmdletBinding(SupportsShouldProcess)]
param([switch]$Force)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'LabCommon.psm1') -Force
Import-LabAdModule
Assert-LabDomain -Force:$Force

$server = 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
$client = 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
$settings = @(
    @{ Key = $server; ValueName = 'SMB1'; Value = 0 },                        # SMBv1 server off
    @{ Key = $server; ValueName = 'RequireSecuritySignature'; Value = 1 },    # SMB signing required (server)
    @{ Key = $client; ValueName = 'RequireSecuritySignature'; Value = 1 },    # SMB signing required (client)
    @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'; ValueName = 'LmCompatibilityLevel'; Value = 5 }  # NTLMv2 only
)
Set-LabGpoRegistryPolicy -GpoName 'LAB-Legacy-Protocols' -Comment 'SMBv1 off, SMB signing, NTLMv2 only - Lab 03 (W04, W05)' `
    -Settings $settings -WhatIf:$WhatIfPreference -LinkTargets @((Get-ADDomain).DistinguishedName)
