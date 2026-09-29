# Stand-ins for the ActiveDirectory, GroupPolicy and LAPS cmdlets.
#
# They are ALWAYS defined as global functions, so they shadow the real cmdlets even on a machine with RSAT
# installed: tests can never reach a real domain. Each declares the parameters the scripts pass, so Pester
# ParameterFilters and mock bodies can read them by name. They do nothing unless a test mocks them.
$stubs = [ordered]@{
    'Get-ADDomain'                          = 'Identity', 'Server'
    'Get-ADOrganizationalUnit'              = 'Filter', 'Identity'
    'New-ADOrganizationalUnit'              = 'Name', 'Path', 'ProtectedFromAccidentalDeletion'
    'Get-ADGroup'                           = 'Filter', 'Identity', 'Properties'
    'New-ADGroup'                           = 'Name', 'GroupScope', 'GroupCategory', 'Path'
    'Get-ADGroupMember'                     = 'Identity'
    'Add-ADGroupMember'                     = 'Identity', 'Members'
    'Remove-ADGroupMember'                  = 'Identity', 'Members'
    'Get-ADUser'                            = 'Filter', 'Identity', 'Properties'
    'New-ADUser'                            = 'Name', 'GivenName', 'Surname', 'SamAccountName', 'UserPrincipalName',
                                              'Department', 'Path', 'AccountPassword', 'ChangePasswordAtLogon', 'Enabled'
    'Disable-ADAccount'                     = 'Identity'
    'Get-ADComputer'                        = 'Filter', 'Identity', 'Properties'
    'Get-ADObject'                          = 'Identity', 'SearchBase', 'Filter', 'Properties'
    'Set-ADObject'                          = 'Identity', 'Replace'
    'Get-ADServiceAccount'                  = 'Filter', 'Identity'
    'New-ADServiceAccount'                  = 'Name', 'DNSHostName', 'PrincipalsAllowedToRetrieveManagedPassword', 'Path'
    'Get-KdsRootKey'                        = @()
    'Add-KdsRootKey'                        = 'EffectiveTime'
    'Get-ADFineGrainedPasswordPolicy'       = 'Filter', 'Identity', 'Properties'
    'New-ADFineGrainedPasswordPolicy'       = 'Name', 'Precedence', 'MinPasswordLength', 'ComplexityEnabled',
                                              'LockoutThreshold', 'LockoutDuration', 'LockoutObservationWindow', '[switch]PassThru'
    'Add-ADFineGrainedPasswordPolicySubject' = 'Identity', 'Subjects'
    'Get-GPO'                               = 'Name', 'Guid'
    'New-GPO'                               = 'Name', 'Comment'
    'Import-GPO'                            = 'BackupId', 'TargetName', 'Path', '[switch]CreateIfNeeded'
    'Get-GPRegistryValue'                   = 'Name', 'Key', 'ValueName'
    'Set-GPRegistryValue'                   = 'Name', 'Key', 'ValueName', 'Type', 'Value'
    'Get-GPInheritance'                     = 'Target'
    'New-GPLink'                            = 'Name', 'Target', 'Order'
    'Set-GPLink'                            = 'Name', 'Target', 'Order'
    'Update-LapsADSchema'                   = @()
    'Set-LapsADComputerSelfPermission'      = 'Identity'
    'Set-LapsADReadPasswordPermission'      = 'Identity', 'AllowedPrincipals'
}
foreach ($name in $stubs.Keys) {
    # '[switch]Name' declares a switch parameter; anything else is a normal (untyped) parameter.
    $params = ($stubs[$name] | ForEach-Object { if ($_ -like '`[switch`]*') { '[switch]$' + $_.Substring(8) } else { '$' + $_ } }) -join ', '
    # SupportsShouldProcess lets callers pass -Confirm:$false / -WhatIf like the real cmdlets accept.
    $body = "[CmdletBinding(SupportsShouldProcess)] param($params)"
    Set-Item -Path "function:global:$name" -Value ([scriptblock]::Create($body))
}

$script:RepoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$script:ScriptsDir = Join-Path $script:RepoRoot 'scripts'
Import-Module (Join-Path $script:ScriptsDir 'LabCommon.psm1') -Force
