#Requires -Version 5.1
<#
.SYNOPSIS
    Fixes W10: stronger domain password and lockout policy, plus a stricter policy for Tier 0 admins.
.DESCRIPTION
    Domain policy: minimum length 14, complexity on, lockout after 10 failed attempts for 15 minutes.
    Fine-grained policy "LAB-Tier0-Admins" (applied to GG-Tier0-Admins): minimum length 20, lockout after 5.
    Run Set-TieredAdminModel.ps1 first (it creates GG-Tier0-Admins).
    Idempotent and -WhatIf aware. Refuses to run outside corp.internal unless -Force.
#>
[CmdletBinding(SupportsShouldProcess)]
param([switch]$Force)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'LabCommon.psm1') -Force
Import-LabAdModule
Assert-LabDomain -Force:$Force
$domain = Get-ADDomain
$window = New-TimeSpan -Minutes 15

$policy = Get-ADDefaultDomainPasswordPolicy -Identity $domain.DNSRoot
if ($policy.MinPasswordLength -lt 14 -or $policy.LockoutThreshold -ne 10 -or -not $policy.ComplexityEnabled) {
    if ($PSCmdlet.ShouldProcess($domain.DNSRoot, 'Set domain password policy (length 14, lockout 10)')) {
        Set-ADDefaultDomainPasswordPolicy -Identity $domain.DNSRoot -MinPasswordLength 14 -ComplexityEnabled $true `
            -LockoutThreshold 10 -LockoutDuration $window -LockoutObservationWindow $window
        Write-LabChange -Action 'SetPasswordPolicy' -Target $domain.DNSRoot -Detail 'length 14, lockout 10'
    }
}

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
