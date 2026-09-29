BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:Build = Join-Path $script:ScriptsDir 'build\New-LabDomainStructure.ps1'
}

Describe 'New-LabDomainStructure' {
    BeforeEach {
        Mock Get-ADDomain -ModuleName LabCommon { [pscustomobject]@{ DNSRoot = 'corp.internal'; DistinguishedName = 'DC=corp,DC=internal' } }
        Mock Get-ADDomain { [pscustomobject]@{ DNSRoot = 'corp.internal'; DistinguishedName = 'DC=corp,DC=internal' } }
        Mock Write-LabChange {}
        Mock New-ADOrganizationalUnit {}
        Mock New-ADGroup {}
        Mock New-ADUser {}
        Mock Add-ADGroupMember {}
    }

    Context 'empty domain' {
        BeforeEach {
            Mock Get-ADOrganizationalUnit { $null }
            Mock Get-ADGroup { $null }
            Mock Get-ADUser { $null }
        }

        It 'creates every OU, group and user' {
            & $script:Build -UserCount 5
            Should -Invoke New-ADOrganizationalUnit -Times 17 -Exactly
            # Member servers (Tier 1) get their own OU, apart from the workstation OUs (Tier 2).
            Should -Invoke New-ADOrganizationalUnit -Times 1 -Exactly -ParameterFilter { $Name -eq 'Servers' -and $Path -eq 'OU=Corp,DC=corp,DC=internal' }
            Should -Invoke New-ADGroup -Times 4 -Exactly
            Should -Invoke New-ADUser -Times 5 -Exactly
        }

        It 'gives users a SecureString password and forces a change at logon' {
            & $script:Build -UserCount 1
            Should -Invoke New-ADUser -Times 1 -ParameterFilter {
                $AccountPassword -is [securestring] -and $ChangePasswordAtLogon -eq $true
            }
        }

        It 'creates the parent OU before its children' {
            $global:LabTestOrder = @()
            Mock New-ADOrganizationalUnit { $global:LabTestOrder += "OU=$Name,$Path" }
            & $script:Build -UserCount 1
            $global:LabTestOrder.IndexOf('OU=Corp,DC=corp,DC=internal') | Should -BeLessThan $global:LabTestOrder.IndexOf('OU=Finance,OU=Corp,DC=corp,DC=internal')
        }

        It 'changes nothing with -WhatIf' {
            & $script:Build -UserCount 5 -WhatIf
            Should -Invoke New-ADOrganizationalUnit -Times 0 -Exactly
            Should -Invoke New-ADUser -Times 0 -Exactly
        }
    }

    Context 'everything already exists' {
        It 'makes no change (idempotent)' {
            Mock Get-ADOrganizationalUnit { [pscustomobject]@{ Name = 'x' } }
            Mock Get-ADGroup { [pscustomobject]@{ Name = 'x' } }
            Mock Get-ADUser { [pscustomobject]@{ SamAccountName = 'x' } }
            & $script:Build -UserCount 5
            Should -Invoke New-ADOrganizationalUnit -Times 0 -Exactly
            Should -Invoke New-ADGroup -Times 0 -Exactly
            Should -Invoke New-ADUser -Times 0 -Exactly
        }
    }

    It 'refuses to run on another domain' {
        Mock Get-ADDomain -ModuleName LabCommon { [pscustomobject]@{ DNSRoot = 'contoso.com' } }
        { & $script:Build -UserCount 1 } | Should -Throw '*only runs against the lab domain*'
        Should -Invoke New-ADOrganizationalUnit -Times 0 -Exactly
    }

    It 'never writes a password to disk' {
        (Get-Content $script:Build -Raw) | Should -Not -Match '(Out-File|Set-Content|Export-Csv).*[Pp]assword'
    }
}
