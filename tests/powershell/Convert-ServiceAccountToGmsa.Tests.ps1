BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:Target = Join-Path $script:ScriptsDir 'harden\Convert-ServiceAccountToGmsa.ps1'
}

Describe 'Convert-ServiceAccountToGmsa' {
    BeforeEach {
        $domain = [pscustomobject]@{ DNSRoot = 'corp.internal'; DistinguishedName = 'DC=corp,DC=internal' }
        Mock Get-ADDomain -ModuleName LabCommon { $domain }
        Mock Get-ADDomain { $domain }
        Mock Write-LabChange {}
        Mock Add-KdsRootKey {}
        Mock New-ADServiceAccount {}
        Mock Remove-ADGroupMember {}
        Mock Disable-ADAccount {}
    }

    Context 'weakness present' {
        BeforeEach {
            Mock Get-KdsRootKey { $null }
            Mock Get-ADServiceAccount { $null }
            Mock Get-ADGroupMember { [pscustomobject]@{ SamAccountName = 'svc-app' } }
        }
        It 'creates the KDS key and the gMSA, and removes svc-app from Domain Admins' {
            & $script:Target
            Should -Invoke Add-KdsRootKey -Times 1 -Exactly
            Should -Invoke New-ADServiceAccount -Times 1 -Exactly -ParameterFilter {
                $Name -eq 'gmsa-app' -and $PrincipalsAllowedToRetrieveManagedPassword -eq 'app01$'
            }
            Should -Invoke Remove-ADGroupMember -Times 1 -Exactly -ParameterFilter {
                $Identity -eq 'Domain Admins' -and $Members -eq 'svc-app'
            }
        }
        It 'does not disable the old account unless asked' {
            & $script:Target
            Should -Invoke Disable-ADAccount -Times 0 -Exactly
        }
        It 'changes nothing with -WhatIf' {
            & $script:Target -WhatIf
            Should -Invoke New-ADServiceAccount -Times 0 -Exactly
            Should -Invoke Remove-ADGroupMember -Times 0 -Exactly
        }
    }

    It 'makes no change when already fixed (idempotent)' {
        Mock Get-KdsRootKey { 'key' }
        Mock Get-ADServiceAccount { 'gmsa' }
        Mock Get-ADGroupMember { [pscustomobject]@{ SamAccountName = 'administrator' } }
        & $script:Target
        Should -Invoke Add-KdsRootKey -Times 0 -Exactly
        Should -Invoke New-ADServiceAccount -Times 0 -Exactly
        Should -Invoke Remove-ADGroupMember -Times 0 -Exactly
    }

    It 'refuses to run on another domain' {
        Mock Get-ADDomain -ModuleName LabCommon { [pscustomobject]@{ DNSRoot = 'xcorp.internal' } }
        { & $script:Target } | Should -Throw '*only runs against the lab domain*'
        Should -Invoke New-ADServiceAccount -Times 0 -Exactly
    }
}
