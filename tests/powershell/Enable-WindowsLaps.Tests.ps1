BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:Target = Join-Path $script:ScriptsDir 'harden\Enable-WindowsLaps.ps1'
    $global:LabTestSid = [System.Security.Principal.SecurityIdentifier]'S-1-5-21-1-2-3-1105'
}

Describe 'Enable-WindowsLaps' {
    BeforeEach {
        $domain = [pscustomobject]@{ DNSRoot = 'corp.internal'; DistinguishedName = 'DC=corp,DC=internal'; SubordinateReferences = @() }
        Mock Get-ADDomain -ModuleName LabCommon { $domain }
        Mock Get-ADDomain { $domain }
        Mock Get-ADGroup { [pscustomobject]@{ SID = $global:LabTestSid } }
        Mock Write-LabChange {}
        Mock Update-LapsADSchema {}
        Mock Set-LapsADComputerSelfPermission {}
        Mock Set-LapsADReadPasswordPermission {}
        Mock Set-LabGpoRegistryPolicy {}
    }

    Context 'no LAPS yet' {
        BeforeEach { Mock Get-ADObject { $null } }

        It 'extends the schema and configures the LAPS GPO on the 3 computer OUs' {
            & $script:Target
            Should -Invoke Update-LapsADSchema -Times 1 -Exactly
            Should -Invoke Set-LabGpoRegistryPolicy -Times 1 -Exactly -ParameterFilter {
                $GpoName -eq 'LAB-Windows-LAPS' -and @($LinkTargets).Count -eq 3 -and
                ($Settings | Where-Object ValueName -eq 'PasswordLength').Value -eq 20
            }
        }
        It 'uses the Windows LAPS group-policy key (not the MDM/CSP key)' {
            & $script:Target
            Should -Invoke Set-LabGpoRegistryPolicy -Times 1 -Exactly -ParameterFilter {
                -not ($Settings | Where-Object Key -ne 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS')
            }
        }
        It 'encrypts the password so only GG-Tier2-Admins can decrypt it' {
            & $script:Target
            Should -Invoke Set-LabGpoRegistryPolicy -Times 1 -Exactly -ParameterFilter {
                $p = $Settings | Where-Object ValueName -eq 'ADPasswordEncryptionPrincipal'
                ($Settings | Where-Object ValueName -eq 'ADPasswordEncryptionEnabled').Value -eq 1 -and
                $p.Type -eq 'String' -and $p.Value -eq 'S-1-5-21-1-2-3-1105'
            }
            Should -Invoke Get-ADGroup -ParameterFilter { $Identity -eq 'GG-Tier2-Admins' }
        }
        It 'lets only Tier 2 admins read workstation passwords' {
            & $script:Target
            Should -Invoke Set-LapsADReadPasswordPermission -Times 3 -Exactly -ParameterFilter { $AllowedPrincipals -eq 'GG-Tier2-Admins' }
        }
        It 'changes nothing with -WhatIf' {
            & $script:Target -WhatIf
            Should -Invoke Update-LapsADSchema -Times 0 -Exactly
            Should -Invoke Set-LapsADReadPasswordPermission -Times 0 -Exactly
            Should -Invoke Set-LabGpoRegistryPolicy -Times 1 -Exactly -ParameterFilter { $WhatIf }
        }
    }

    It 'does not extend the schema again when LAPS is already deployed' {
        Mock Get-ADObject { 'schema-attribute' }
        & $script:Target
        Should -Invoke Update-LapsADSchema -Times 0 -Exactly
    }
}
