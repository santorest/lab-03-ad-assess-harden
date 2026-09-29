#Requires -Version 5.1
<#
.SYNOPSIS
    Fixes W01/W02: replaces the svc-app account (Domain Admin, password never expires) with a gMSA.
.DESCRIPTION
    1. Ensures a KDS root key exists (needed for gMSAs).
    2. Creates the group-managed service account gmsa-app, retrievable only by app01.
    3. Removes svc-app from Domain Admins.
    4. With -DisableOldAccount, disables svc-app (do this after switching the application to gmsa-app).
    Idempotent and -WhatIf aware. Refuses to run outside corp.internal unless -Force.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$OldAccount = 'svc-app',
    [string]$GmsaName = 'gmsa-app',
    [string]$AppServer = 'app01',
    [switch]$DisableOldAccount,
    [switch]$Force
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'LabCommon.psm1') -Force
Import-LabAdModule
Assert-LabDomain -Force:$Force
$domain = Get-ADDomain

if (-not (Get-KdsRootKey)) {
    if ($PSCmdlet.ShouldProcess('KDS root key', 'Create (effective immediately - lab only)')) {
        # Lab shortcut: backdating makes the key usable at once. In production, create it and wait 10 hours.
        Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10)) | Out-Null
        Write-LabChange -Action 'CreateKdsRootKey' -Target $domain.DNSRoot
    }
}

if (-not (Get-ADServiceAccount -Filter "Name -eq '$GmsaName'")) {
    if ($PSCmdlet.ShouldProcess($GmsaName, 'Create gMSA')) {
        New-ADServiceAccount -Name $GmsaName -DNSHostName "$GmsaName.$($domain.DNSRoot)" `
            -PrincipalsAllowedToRetrieveManagedPassword "$AppServer$" `
            -Path "OU=ServiceAccounts,OU=Corp,$($domain.DistinguishedName)"
        Write-LabChange -Action 'CreateGmsa' -Target $GmsaName -Detail "retrievable by $AppServer"
    }
}

$isDomainAdmin = @(Get-ADGroupMember -Identity 'Domain Admins' | Where-Object { $_.SamAccountName -eq $OldAccount })
if ($isDomainAdmin) {
    if ($PSCmdlet.ShouldProcess($OldAccount, 'Remove from Domain Admins')) {
        Remove-ADGroupMember -Identity 'Domain Admins' -Members $OldAccount -Confirm:$false
        Write-LabChange -Action 'RemoveFromDomainAdmins' -Target $OldAccount
    }
}

if ($DisableOldAccount) {
    $old = Get-ADUser -Identity $OldAccount -Properties Enabled
    if ($old.Enabled -and $PSCmdlet.ShouldProcess($OldAccount, 'Disable')) {
        Disable-ADAccount -Identity $OldAccount
        Write-LabChange -Action 'DisableAccount' -Target $OldAccount
    }
}
