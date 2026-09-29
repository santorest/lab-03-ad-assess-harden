BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:Target = Join-Path $script:ScriptsDir 'harden\Set-TieredAdminModel.ps1'
    $global:LabTestSid = [System.Security.Principal.SecurityIdentifier]'S-1-5-21-1-2-3-512'
}

Describe 'Set-TieredAdminModel' {
    BeforeEach {
        $domain = [pscustomobject]@{ DNSRoot = 'corp.internal'; DistinguishedName = 'DC=corp,DC=internal' }
        Mock Get-ADDomain -ModuleName LabCommon { $domain }
        Mock Get-ADDomain { $domain }
        Mock Write-LabChange {}
        Mock New-ADGroup {}
        Mock Set-Acl {}
        Mock Get-Acl { New-Object System.DirectoryServices.ActiveDirectorySecurity }
        Mock New-GPO { [pscustomobject]@{ Id = [guid]::NewGuid() } }
        Mock New-GPLink {}
        Mock Set-Content {}
        Mock New-Item {}
        Mock Set-ADObject {}
        Mock Get-ADObject { [pscustomobject]@{ versionNumber = 1 } }
        Mock Test-Path { $false }
        Mock Get-GPInheritance { [pscustomobject]@{ GpoLinks = @() } }
        Mock Set-LabGpoSecurityTemplate {}
    }

    It 'refuses to run on another domain' {
        Mock Get-ADDomain -ModuleName LabCommon { [pscustomobject]@{ DNSRoot = 'corp.internal.evil' } }
        { & $script:Target } | Should -Throw '*only runs against the lab domain*'
        Should -Invoke New-ADGroup -Times 0 -Exactly
    }

    It 'changes nothing with -WhatIf' {
        Mock Get-ADGroup { param($Filter, $Identity) if ($Filter) { $null } else { [pscustomobject]@{ SID = $global:LabTestSid } } }
        Mock Get-GPO { $null }
        & $script:Target -WhatIf
        Should -Invoke New-ADGroup -Times 0 -Exactly
        Should -Invoke Set-Acl -Times 0 -Exactly
        Should -Invoke New-GPO -Times 0 -Exactly
        Should -Invoke Set-Content -Times 0 -Exactly
    }

    It 'creates the three tier groups, delegates reset on the 3 user OUs and links the GPO' {
        Mock Get-ADGroup { param($Filter, $Identity) if ($Filter) { $null } else { [pscustomobject]@{ SID = $global:LabTestSid } } }
        Mock Get-GPO { $null }
        & $script:Target
        Should -Invoke New-ADGroup -Times 3 -Exactly
        Should -Invoke Set-Acl -Times 3 -Exactly
        Should -Invoke New-GPLink -Times 3 -Exactly
    }

    It 'writes deny-logon rights for the Tier 0 SIDs through the shared security-template helper' {
        Mock Get-ADGroup { param($Filter, $Identity) if ($Filter) { 'exists' } else { [pscustomobject]@{ SID = $global:LabTestSid } } }
        Mock Get-GPO { [pscustomobject]@{ Id = [guid]'11111111-2222-3333-4444-555555555555' } }
        Mock Set-LabGpoSecurityTemplate {}
        & $script:Target
        Should -Invoke Set-LabGpoSecurityTemplate -Times 1 -Exactly -ParameterFilter {
            $GpoId -eq [guid]'11111111-2222-3333-4444-555555555555' -and
            $Sections['Privilege Rights']['SeDenyInteractiveLogonRight'] -match '\*S-1-5-21-1-2-3-512'
        }
    }

    It 'previews with -WhatIf on a fresh domain where the tier groups do not exist yet' {
        Mock Get-ADGroup {
            param($Filter, $Identity)
            if ($Filter) { $null }
            elseif ($Identity -like 'GG-Tier*') { throw "Cannot find an object with identity: '$Identity'" }
            else { [pscustomobject]@{ SID = $global:LabTestSid } }
        }
        Mock Get-GPO { $null }
        { & $script:Target -WhatIf -WarningAction SilentlyContinue } | Should -Not -Throw
        Should -Invoke New-GPO -Times 0 -Exactly
    }
}
