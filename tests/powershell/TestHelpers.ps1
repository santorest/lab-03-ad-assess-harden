# Stand-ins for the RSAT ActiveDirectory / GroupPolicy cmdlets so tests run on machines without them.
# Pester can only mock commands that exist; these do nothing unless a test mocks them.
$adCommands = @(
    'Get-ADDomain', 'Get-ADOrganizationalUnit', 'New-ADOrganizationalUnit', 'Get-ADGroup', 'New-ADGroup',
    'Get-ADGroupMember', 'Add-ADGroupMember', 'Remove-ADGroupMember', 'Get-ADUser', 'New-ADUser', 'Set-ADUser',
    'Disable-ADAccount', 'Get-ADComputer', 'Get-ADServiceAccount', 'New-ADServiceAccount', 'Get-KdsRootKey',
    'Add-KdsRootKey', 'Get-ADDefaultDomainPasswordPolicy', 'Set-ADDefaultDomainPasswordPolicy',
    'Get-ADFineGrainedPasswordPolicy', 'New-ADFineGrainedPasswordPolicy', 'Add-ADFineGrainedPasswordPolicySubject',
    'Get-GPO', 'New-GPO', 'New-GPLink', 'Import-GPO', 'Get-GPRegistryValue', 'Set-GPRegistryValue',
    'Update-LapsADSchema', 'Set-LapsADComputerSelfPermission', 'Set-LapsADReadPasswordPermission',
    'Get-ItemProperty', 'Get-Service', 'Stop-Service', 'Set-Service', 'Get-SmbServerConfiguration',
    'Set-SmbServerConfiguration', 'Get-ADObject', 'Set-ADObject', 'Get-GPInheritance'
)
foreach ($name in $adCommands) {
    if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
        Set-Item -Path "function:global:$name" -Value { param() }
    }
}

$script:RepoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$script:ScriptsDir = Join-Path $script:RepoRoot 'scripts'
Import-Module (Join-Path $script:ScriptsDir 'LabCommon.psm1') -Force
