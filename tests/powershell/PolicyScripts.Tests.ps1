BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:Harden = Join-Path $script:ScriptsDir 'harden'
    $script:Domain = [pscustomobject]@{ DNSRoot = 'corp.internal'; DistinguishedName = 'DC=corp,DC=internal' }
}

Describe 'GPO registry scripts (Disable-LegacyProtocols, Set-LdapSigning)' -ForEach @(
    @{ Script = 'Disable-LegacyProtocols.ps1'; Gpo = 'LAB-Legacy-Protocols'; Values = 4; Key = 'LmCompatibilityLevel'; Expect = 5 }
    @{ Script = 'Set-LdapSigning.ps1'; Gpo = 'LAB-LDAP-Signing'; Values = 2; Key = 'LdapEnforceChannelBinding'; Expect = 2 }
) {
    BeforeEach {
        Mock Get-ADDomain -ModuleName LabCommon { $script:Domain }
        Mock Get-ADDomain { $script:Domain }
        # The helper lives in LabCommon, so its cmdlets are mocked inside that module.
        Mock Write-LabChange -ModuleName LabCommon {}
        Mock Get-GPO -ModuleName LabCommon { $null }
        Mock New-GPO -ModuleName LabCommon { [pscustomobject]@{ DisplayName = 'x' } }
        Mock Get-GPRegistryValue -ModuleName LabCommon { $null }
        Mock Set-GPRegistryValue -ModuleName LabCommon {}
        Mock Get-GPInheritance -ModuleName LabCommon { [pscustomobject]@{ GpoLinks = @() } }
        Mock New-GPLink -ModuleName LabCommon {}
    }

    It '<Script> creates <Gpo> with its settings and links it' {
        & (Join-Path $script:Harden $Script)
        Should -Invoke New-GPO -ModuleName LabCommon -Times 1 -Exactly -ParameterFilter { $Name -eq $Gpo }
        Should -Invoke Set-GPRegistryValue -ModuleName LabCommon -Times $Values -Exactly
        Should -Invoke Set-GPRegistryValue -ModuleName LabCommon -Times 1 -Exactly -ParameterFilter { $ValueName -eq $Key -and $Value -eq $Expect }
        Should -Invoke New-GPLink -ModuleName LabCommon -Times 1 -Exactly
    }

    It '<Script> changes nothing with -WhatIf (regression: -WhatIf must reach the LabCommon helper)' {
        & (Join-Path $script:Harden $Script) -WhatIf
        Should -Invoke New-GPO -ModuleName LabCommon -Times 0 -Exactly
        Should -Invoke Set-GPRegistryValue -ModuleName LabCommon -Times 0 -Exactly
        Should -Invoke New-GPLink -ModuleName LabCommon -Times 0 -Exactly
    }

    It '<Script> refuses to run on another domain' {
        Mock Get-ADDomain -ModuleName LabCommon { [pscustomobject]@{ DNSRoot = 'xcorp.internal' } }
        { & (Join-Path $script:Harden $Script) } | Should -Throw '*only runs against the lab domain*'
        Should -Invoke New-GPO -ModuleName LabCommon -Times 0 -Exactly
    }
}

Describe 'Set-PasswordPolicy' {
    BeforeEach {
        Mock Get-ADDomain -ModuleName LabCommon { $script:Domain }
        Mock Get-ADDomain { $script:Domain }
        Mock Write-LabChange {}
        Mock Set-ADDefaultDomainPasswordPolicy {}
        Mock New-ADFineGrainedPasswordPolicy { [pscustomobject]@{ AppliesTo = @() } }
        Mock Add-ADFineGrainedPasswordPolicySubject {}
    }
    It 'raises the domain policy to length 14 / lockout 10 and creates the Tier 0 policy (length 20)' {
        Mock Get-ADDefaultDomainPasswordPolicy { [pscustomobject]@{ MinPasswordLength = 7; LockoutThreshold = 0; ComplexityEnabled = $true } }
        Mock Get-ADFineGrainedPasswordPolicy { $null }
        & (Join-Path $script:Harden 'Set-PasswordPolicy.ps1')
        Should -Invoke Set-ADDefaultDomainPasswordPolicy -Times 1 -Exactly -ParameterFilter { $MinPasswordLength -eq 14 -and $LockoutThreshold -eq 10 }
        Should -Invoke New-ADFineGrainedPasswordPolicy -Times 1 -Exactly -ParameterFilter { $MinPasswordLength -eq 20 }
        Should -Invoke Add-ADFineGrainedPasswordPolicySubject -Times 1 -Exactly -ParameterFilter { $Subjects -eq 'GG-Tier0-Admins' }
    }
    It 'changes nothing when already compliant' {
        Mock Get-ADDefaultDomainPasswordPolicy { [pscustomobject]@{ MinPasswordLength = 14; LockoutThreshold = 10; ComplexityEnabled = $true } }
        Mock Get-ADFineGrainedPasswordPolicy { [pscustomobject]@{ AppliesTo = @('CN=GG-Tier0-Admins,OU=Tier0,OU=Admin,DC=corp,DC=internal') } }
        & (Join-Path $script:Harden 'Set-PasswordPolicy.ps1')
        Should -Invoke Set-ADDefaultDomainPasswordPolicy -Times 0 -Exactly
        Should -Invoke New-ADFineGrainedPasswordPolicy -Times 0 -Exactly
        Should -Invoke Add-ADFineGrainedPasswordPolicySubject -Times 0 -Exactly
    }
    It 'changes nothing with -WhatIf' {
        Mock Get-ADDefaultDomainPasswordPolicy { [pscustomobject]@{ MinPasswordLength = 7; LockoutThreshold = 0; ComplexityEnabled = $true } }
        Mock Get-ADFineGrainedPasswordPolicy { $null }
        & (Join-Path $script:Harden 'Set-PasswordPolicy.ps1') -WhatIf
        Should -Invoke Set-ADDefaultDomainPasswordPolicy -Times 0 -Exactly
        Should -Invoke New-ADFineGrainedPasswordPolicy -Times 0 -Exactly
    }
}

Describe 'Disable-SpoolerOnDC' {
    BeforeEach {
        Mock Get-ADDomain -ModuleName LabCommon { $script:Domain }
        Mock Write-LabChange {}
        Mock Stop-Service {}
        Mock Set-Service {}
    }
    It 'stops and disables a running Spooler on a DC' {
        Mock Get-CimInstance { [pscustomobject]@{ DomainRole = 5 } }
        Mock Get-Service { [pscustomobject]@{ Status = 'Running'; StartType = 'Automatic' } }
        & (Join-Path $script:Harden 'Disable-SpoolerOnDC.ps1')
        Should -Invoke Stop-Service -Times 1 -Exactly
        Should -Invoke Set-Service -Times 1 -Exactly -ParameterFilter { $StartupType -eq 'Disabled' }
    }
    It 'changes nothing when already stopped and disabled' {
        Mock Get-CimInstance { [pscustomobject]@{ DomainRole = 5 } }
        Mock Get-Service { [pscustomobject]@{ Status = 'Stopped'; StartType = 'Disabled' } }
        & (Join-Path $script:Harden 'Disable-SpoolerOnDC.ps1')
        Should -Invoke Stop-Service -Times 0 -Exactly
        Should -Invoke Set-Service -Times 0 -Exactly
    }
    It 'refuses to run on a machine that is not a DC' {
        Mock Get-CimInstance { [pscustomobject]@{ DomainRole = 1 } }
        { & (Join-Path $script:Harden 'Disable-SpoolerOnDC.ps1') } | Should -Throw '*not a domain controller*'
    }
}

Describe 'Get-StaleAccounts' {
    BeforeEach {
        Mock Get-ADDomain -ModuleName LabCommon { $script:Domain }
        Mock Write-LabChange {}
        Mock Disable-ADAccount {}
        Mock Get-ADUser {
            [pscustomobject]@{ SamAccountName = 'old.user'; ObjectClass = 'user'; LastLogonDate = (Get-Date).AddDays(-200); whenCreated = (Get-Date).AddDays(-400) }
            [pscustomobject]@{ SamAccountName = 'krbtgt'; ObjectClass = 'user'; LastLogonDate = $null; whenCreated = (Get-Date).AddDays(-900) }
            [pscustomobject]@{ SamAccountName = 'active.user'; ObjectClass = 'user'; LastLogonDate = (Get-Date).AddDays(-2); whenCreated = (Get-Date).AddDays(-400) }
        }
        Mock Get-ADComputer { [pscustomobject]@{ SamAccountName = 'ws99$'; ObjectClass = 'computer'; LastLogonDate = $null; whenCreated = (Get-Date).AddDays(-120) } }
    }
    It 'reports stale accounts, skips built-ins, and disables nothing by default' {
        $result = & (Join-Path $script:Harden 'Get-StaleAccounts.ps1')
        $result.Name | Should -Be @('old.user', 'ws99$')
        ($result | Where-Object Name -eq 'old.user').DaysInactive | Should -BeGreaterThan 90
        Should -Invoke Disable-ADAccount -Times 0 -Exactly
    }
    It 'disables them only with -Disable' {
        & (Join-Path $script:Harden 'Get-StaleAccounts.ps1') -Disable | Out-Null
        Should -Invoke Disable-ADAccount -Times 2 -Exactly
    }
    It 'disables nothing with -Disable -WhatIf' {
        & (Join-Path $script:Harden 'Get-StaleAccounts.ps1') -Disable -WhatIf | Out-Null
        Should -Invoke Disable-ADAccount -Times 0 -Exactly
    }
}

Describe 'Import-SecurityBaseline' {
    BeforeEach {
        Mock Get-ADDomain -ModuleName LabCommon { $script:Domain }
        Mock Get-ADDomain { $script:Domain }
        Mock Write-LabChange {}
        Mock Import-GPO {}
        Mock New-GPLink {}
        Mock Get-GPO { $null }
        Mock Get-GPInheritance { [pscustomobject]@{ GpoLinks = @() } }
    }
    It 'fails clearly when the baseline folder has no GPO backups' {
        { & (Join-Path $script:Harden 'Import-SecurityBaseline.ps1') -BaselinePath (Join-Path $TestDrive 'nothing') } |
            Should -Throw '*No GPO backups found*'
    }
    It 'imports the DC and member-server baselines and links the DC one to the Domain Controllers OU' {
        $base = Join-Path $TestDrive 'baseline'
        New-Item -ItemType Directory -Path (Join-Path $base 'GPOs') -Force | Out-Null
        Set-Content -Path (Join-Path $base 'GPOs\manifest.xml') -Value ('<Backups>' +
            '<BackupInst><GPODisplayName><![CDATA[MSFT Windows Server 2022 - Domain Controller]]></GPODisplayName><ID><![CDATA[{A1}]]></ID></BackupInst>' +
            '<BackupInst><GPODisplayName><![CDATA[MSFT Windows Server 2022 - Member Server]]></GPODisplayName><ID><![CDATA[{A2}]]></ID></BackupInst>' +
            '</Backups>')
        & (Join-Path $script:Harden 'Import-SecurityBaseline.ps1') -BaselinePath $base
        Should -Invoke Import-GPO -Times 2 -Exactly
        Should -Invoke New-GPLink -Times 1 -Exactly -ParameterFilter { $Target -eq 'OU=Domain Controllers,DC=corp,DC=internal' }
    }
}
