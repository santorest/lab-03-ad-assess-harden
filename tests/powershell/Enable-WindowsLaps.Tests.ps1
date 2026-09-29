BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:Target = Join-Path $script:ScriptsDir 'harden\Enable-WindowsLaps.ps1'
}

Describe 'Enable-WindowsLaps' {
    BeforeEach {
        $domain = [pscustomobject]@{ DNSRoot = 'corp.internal'; DistinguishedName = 'DC=corp,DC=internal'; SubordinateReferences = @() }
        Mock Get-ADDomain -ModuleName LabCommon { $domain }
        Mock Get-ADDomain { $domain }
        Mock Write-LabChange {}
        Mock Update-LapsADSchema {}
        Mock Set-LapsADComputerSelfPermission {}
        Mock Set-LapsADReadPasswordPermission {}
        Mock New-GPO { [pscustomobject]@{ DisplayName = 'LAB-Windows-LAPS'; Id = [guid]::NewGuid() } }
        Mock Set-GPRegistryValue {}
        Mock New-GPLink {}
    }

    Context 'no LAPS yet' {
        BeforeEach {
            Mock Get-ADObject { $null }
            Mock Get-GPO { $null }
            Mock Get-GPRegistryValue { $null }
            Mock Get-GPInheritance { [pscustomobject]@{ GpoLinks = @() } }
        }
        It 'extends the schema, creates the GPO with five settings and links it to the 3 computer OUs' {
            & $script:Target
            Should -Invoke Update-LapsADSchema -Times 1 -Exactly
            Should -Invoke New-GPO -Times 1 -Exactly
            Should -Invoke Set-GPRegistryValue -Times 5 -Exactly
            Should -Invoke Set-GPRegistryValue -Times 1 -Exactly -ParameterFilter { $ValueName -eq 'PasswordLength' -and $Value -eq 20 }
            Should -Invoke New-GPLink -Times 3 -Exactly
        }
        It 'lets only Tier 2 admins read workstation passwords' {
            & $script:Target
            Should -Invoke Set-LapsADReadPasswordPermission -Times 3 -Exactly -ParameterFilter { $AllowedPrincipals -eq 'GG-Tier2-Admins' }
        }
        It 'changes nothing with -WhatIf' {
            & $script:Target -WhatIf
            Should -Invoke Update-LapsADSchema -Times 0 -Exactly
            Should -Invoke New-GPO -Times 0 -Exactly
            Should -Invoke New-GPLink -Times 0 -Exactly
        }
    }

    It 'creates and links nothing new when LAPS is already deployed (idempotent)' {
        Mock Get-ADObject { 'schema-attribute' }
        Mock Get-GPO { [pscustomobject]@{ DisplayName = 'LAB-Windows-LAPS'; Id = [guid]::NewGuid() } }
        Mock Get-GPRegistryValue {
            $v = @{ BackupDirectory = 2; ADPasswordEncryptionEnabled = 1; PasswordComplexity = 4; PasswordLength = 20; PasswordAgeDays = 30 }
            [pscustomobject]@{ Value = $v[$ValueName] }
        }
        Mock Get-GPInheritance { [pscustomobject]@{ GpoLinks = @([pscustomobject]@{ DisplayName = 'LAB-Windows-LAPS' }) } }
        & $script:Target
        Should -Invoke Update-LapsADSchema -Times 0 -Exactly
        Should -Invoke New-GPO -Times 0 -Exactly
        Should -Invoke Set-GPRegistryValue -Times 0 -Exactly
        Should -Invoke New-GPLink -Times 0 -Exactly
    }
}
