#Requires -Version 5.1
<#
.SYNOPSIS
    Creates the OUs, groups and ~40 fictional users of the corp.internal lab domain.
.DESCRIPTION
    Idempotent: objects that already exist are left alone, so running it twice changes nothing. Supports -WhatIf.
    Users get a random password that nobody sees and must change it at first logon; reset the password of the
    few accounts you actually use in the lab (docs/build.md). No password is ever printed or written to disk.
.EXAMPLE
    .\New-LabDomainStructure.ps1 -WhatIf
    .\New-LabDomainStructure.ps1
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateRange(1, 200)][int]$UserCount = 40,
    [switch]$Force
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'LabCommon.psm1') -Force

Import-LabAdModule
Assert-LabDomain -Force:$Force
$domainDn = (Get-ADDomain).DistinguishedName

# Parents come before children.
$ous = @(
    'OU=Corp', 'OU=Finance,OU=Corp', 'OU=Users,OU=Finance,OU=Corp', 'OU=Computers,OU=Finance,OU=Corp',
    'OU=Operations,OU=Corp', 'OU=Users,OU=Operations,OU=Corp', 'OU=Computers,OU=Operations,OU=Corp',
    'OU=Management,OU=Corp', 'OU=Users,OU=Management,OU=Corp', 'OU=Computers,OU=Management,OU=Corp',
    'OU=ServiceAccounts,OU=Corp', 'OU=Groups,OU=Corp',
    'OU=Admin', 'OU=Tier0,OU=Admin', 'OU=Tier1,OU=Admin', 'OU=Tier2,OU=Admin'
)
$departments = @('Finance', 'Operations', 'Management')
$groups = @('GG-Finance', 'GG-Operations', 'GG-Management', 'GG-Helpdesk')
$firstNames = @('Ana', 'Luis', 'Marta', 'Jorge', 'Sofia', 'Diego', 'Laura', 'Pablo', 'Elena', 'Andres')
$lastNames = @('Rivera', 'Gomez', 'Torres', 'Vargas', 'Rojas', 'Castro')

function New-RandomSecureString {
    [CmdletBinding()]
    [OutputType([securestring])]
    param([int]$Length = 24)
    $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#%*-_=+'
    $bytes = New-Object byte[] $Length
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $secure = New-Object System.Security.SecureString
    foreach ($b in $bytes) { $secure.AppendChar($chars[$b % $chars.Length]) }
    $secure.MakeReadOnly()
    $secure
}

foreach ($ou in $ous) {
    $dn = "$ou,$domainDn"
    if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$dn'")) {
        $name = ($ou -split ',')[0] -replace '^OU=', ''
        $path = (($ou -split ',', 2) | Select-Object -Skip 1) -join ''
        $parent = if ($path) { "$path,$domainDn" } else { $domainDn }
        if ($PSCmdlet.ShouldProcess($dn, 'Create OU')) {
            New-ADOrganizationalUnit -Name $name -Path $parent -ProtectedFromAccidentalDeletion $true
            Write-LabChange -Action 'CreateOU' -Target $dn
        }
    }
}

$groupPath = "OU=Groups,OU=Corp,$domainDn"
foreach ($group in $groups) {
    if (-not (Get-ADGroup -Filter "Name -eq '$group'")) {
        if ($PSCmdlet.ShouldProcess($group, 'Create group')) {
            New-ADGroup -Name $group -GroupScope Global -GroupCategory Security -Path $groupPath
            Write-LabChange -Action 'CreateGroup' -Target $group
        }
    }
}

for ($i = 0; $i -lt $UserCount; $i++) {
    $first = $firstNames[$i % $firstNames.Count]
    $last = $lastNames[[math]::Floor($i / $firstNames.Count) % $lastNames.Count]
    $sam = ('{0}.{1}{2}' -f $first, $last, $i).ToLowerInvariant()
    $department = $departments[$i % $departments.Count]
    if (-not (Get-ADUser -Filter "SamAccountName -eq '$sam'")) {
        if ($PSCmdlet.ShouldProcess($sam, 'Create user')) {
            New-ADUser -Name "$first $last $i" -GivenName $first -Surname $last -SamAccountName $sam `
                -UserPrincipalName "$sam@$(Get-LabDomainName)" -Department $department `
                -Path "OU=Users,OU=$department,OU=Corp,$domainDn" `
                -AccountPassword (New-RandomSecureString) -ChangePasswordAtLogon $true -Enabled $true
            Add-ADGroupMember -Identity "GG-$department" -Members $sam
            Write-LabChange -Action 'CreateUser' -Target $sam -Detail $department
        }
    }
}
