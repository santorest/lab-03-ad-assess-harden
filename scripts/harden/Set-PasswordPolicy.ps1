#Requires -Version 5.1
<#
.SYNOPSIS
    Fixes W10: stronger domain password and lockout policy, plus a stricter policy for Tier 0 admins.
.DESCRIPTION
    Domain policy (Default Domain Policy GPO): minimum length 14, complexity on, lockout after 10 failed
    attempts for 15 minutes. Applies at the next policy refresh on the DCs (or `gpupdate /force`).
    Fine-grained policy "LAB-Tier0-Admins" (applied to GG-Tier0-Admins): minimum length 20, lockout after 5.
    Run Set-TieredAdminModel.ps1 first (it creates GG-Tier0-Admins).
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
$window = New-TimeSpan -Minutes 15

# The Default Domain Policy GPO is authoritative for the domain password and lockout policy: domain controllers
# re-apply its security template, so changing the domain attributes directly would be reverted on the next
# refresh. Merge the settings into its GptTmpl.inf [System Access] instead (only when they differ).
$defaultDomainPolicy = [guid]'31B2F340-016D-11D2-945F-00C04FB984F9'
$domainPolicy = [ordered]@{
    'System Access' = [ordered]@{
        MinimumPasswordLength = '14'
        PasswordComplexity    = '1'
        LockoutBadCount       = '10'
        LockoutDuration       = '15'
        ResetLockoutCount     = '15'
    }
}
Set-LabGpoSecurityTemplate -GpoId $defaultDomainPolicy -Sections $domainPolicy -WhatIf:$WhatIfPreference

$fgppName = 'LAB-Tier0-Admins'
$fgpp = Get-ADFineGrainedPasswordPolicy -Filter "Name -eq '$fgppName'" -Properties AppliesTo
if (-not $fgpp -and $PSCmdlet.ShouldProcess($fgppName, 'Create fine-grained password policy')) {
    $fgpp = New-ADFineGrainedPasswordPolicy -Name $fgppName -Precedence 10 -MinPasswordLength 20 -ComplexityEnabled $true `
        -LockoutThreshold 5 -LockoutDuration $window -LockoutObservationWindow $window -PassThru
    Write-LabChange -Action 'CreateFgpp' -Target $fgppName
}
if ($fgpp) {
    $applied = @($fgpp.AppliesTo | Where-Object { $_ -like 'CN=GG-Tier0-Admins,*' })
    if (-not $applied -and $PSCmdlet.ShouldProcess($fgppName, 'Apply to GG-Tier0-Admins')) {
        Add-ADFineGrainedPasswordPolicySubject -Identity $fgppName -Subjects 'GG-Tier0-Admins'
        Write-LabChange -Action 'ApplyFgpp' -Target $fgppName -Detail 'GG-Tier0-Admins'
    }
}
