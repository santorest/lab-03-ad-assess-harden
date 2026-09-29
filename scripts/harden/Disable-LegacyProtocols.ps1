#Requires -Version 5.1
<#
.SYNOPSIS
    Fixes W04/W05: disables SMBv1, requires SMB signing and allows only NTLMv2 (LmCompatibilityLevel 5).
.DESCRIPTION
    Creates and links the GPO "LAB-Legacy-Protocols" first at the domain root, so it applies to domain controllers,
    servers and workstations. Test application first: an old device that only speaks SMBv1 or NTLMv1 stops
    working, which is the point, but find it before users do (PingCastle and the event logs list them).
    Idempotent and -WhatIf aware. Refuses to run outside corp.internal unless -Force.
#>
[CmdletBinding(SupportsShouldProcess)]
param([switch]$Force)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# Load the shared module once; re-importing would reset it (and any test mocks attached to it).
if (-not (Get-Module LabCommon)) { Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'LabCommon.psm1') }
Import-LabAdModule
Assert-LabDomain -Force:$Force

$settings = @(
    # SMBv1 is not a security option, so it stays a registry-policy value.
    @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; ValueName = 'SMB1'; Value = 0 }
)
# Security options, written like the default GPOs write them (GptTmpl.inf, type 4 = DWORD) so the Default
# Domain Policy can't override them; linked first at the domain root to outrank it.
$securityOptions = [ordered]@{
    'Registry Values' = [ordered]@{
        'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature'     = '4,1'  # SMB signing (server)
        'MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature' = '4,1'  # SMB signing (client)
        'MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel'                              = '4,5'  # NTLMv2 only
    }
}
Set-LabGpoRegistryPolicy -GpoName 'LAB-Legacy-Protocols' -Comment 'SMBv1 off, SMB signing, NTLMv2 only - Lab 03 (W04, W05)' `
    -Settings $settings -SecurityTemplate $securityOptions -LinkFirst -WhatIf:$WhatIfPreference `
    -LinkTargets @((Get-ADDomain).DistinguishedName)
