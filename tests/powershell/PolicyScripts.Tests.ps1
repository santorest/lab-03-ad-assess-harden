BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:Harden = Join-Path $script:ScriptsDir 'harden'
    $global:LabTestDomain = [pscustomobject]@{ DNSRoot = 'corp.internal'; DistinguishedName = 'DC=corp,DC=internal' }
}

Describe 'GPO scripts (Disable-LegacyProtocols, Set-LdapSigning)' -ForEach @(
    # Security options go into the GPO security template (as the default GPOs set them), so they aren't
    # overridden; only SMBv1, which is not a security option, stays a registry-policy value.
    @{ Script = 'Disable-LegacyProtocols.ps1'; Gpo = 'LAB-Legacy-Protocols'; RegistryValues = 1; LinkTarget = 'DC=corp,DC=internal'
       OptionName = 'MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel'; OptionValue = '4,5' }
    @{ Script = 'Set-LdapSigning.ps1'; Gpo = 'LAB-LDAP-Signing'; RegistryValues = 0; LinkTarget = 'OU=Domain Controllers,DC=corp,DC=internal'
       OptionName = 'MACHINE\System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity'; OptionValue = '4,2' }
) {
    BeforeEach {
        Mock Get-ADDomain -ModuleName LabCommon { $global:LabTestDomain }
        Mock Get-ADDomain { $global:LabTestDomain }
        # The helper lives in LabCommon, so its cmdlets are mocked inside that module.
        Mock Write-LabChange -ModuleName LabCommon {}
        Mock Get-GPO -ModuleName LabCommon { $null }
        Mock New-GPO -ModuleName LabCommon { [pscustomobject]@{ DisplayName = 'x'; Id = [guid]::NewGuid() } }
        Mock Get-GPRegistryValue -ModuleName LabCommon { $null }
        Mock Set-GPRegistryValue -ModuleName LabCommon {}
        Mock Set-LabGpoSecurityTemplate -ModuleName LabCommon {}
        Mock Get-GPInheritance -ModuleName LabCommon { [pscustomobject]@{ GpoLinks = @() } }
        Mock New-GPLink -ModuleName LabCommon {}
    }

    It '<Script> creates <Gpo>, writes its security options to the template and links it first' {
        & (Join-Path $script:Harden $Script)
        Should -Invoke New-GPO -ModuleName LabCommon -Times 1 -Exactly -ParameterFilter { $Name -eq $Gpo }
        Should -Invoke Set-GPRegistryValue -ModuleName LabCommon -Times $RegistryValues -Exactly
        Should -Invoke Set-LabGpoSecurityTemplate -ModuleName LabCommon -Times 1 -Exactly -ParameterFilter {
            $Sections['Registry Values'][$OptionName] -eq $OptionValue
        }
        # Order 1 outranks the Default Domain Policy (domain root) and Default Domain Controllers Policy.
        Should -Invoke New-GPLink -ModuleName LabCommon -Times 1 -Exactly -ParameterFilter { $Target -eq $LinkTarget -and $Order -eq 1 }
    }

    It '<Script> changes nothing with -WhatIf (regression: -WhatIf must reach the LabCommon helper)' {
        & (Join-Path $script:Harden $Script) -WhatIf
        Should -Invoke New-GPO -ModuleName LabCommon -Times 0 -Exactly
        Should -Invoke Set-GPRegistryValue -ModuleName LabCommon -Times 0 -Exactly
        Should -Invoke Set-LabGpoSecurityTemplate -ModuleName LabCommon -Times 0 -Exactly -ParameterFilter { -not $WhatIf }
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
        Mock Get-ADDomain -ModuleName LabCommon { $global:LabTestDomain }
        Mock Get-ADDomain { $global:LabTestDomain }
        Mock Write-LabChange {}
        Mock Set-LabGpoSecurityTemplate {}
        Mock New-ADFineGrainedPasswordPolicy { [pscustomobject]@{ AppliesTo = @() } }
        Mock Add-ADFineGrainedPasswordPolicySubject {}
    }
    It 'writes length 14 / lockout 10 into the Default Domain Policy and creates the Tier 0 policy (length 20)' {
        Mock Get-ADFineGrainedPasswordPolicy { $null }
        & (Join-Path $script:Harden 'Set-PasswordPolicy.ps1')
        # The Default Domain Policy GPO is authoritative for domain password settings: DCs re-apply its
        # GptTmpl.inf, so writing the domain attributes directly would be reverted.
        Should -Invoke Set-LabGpoSecurityTemplate -Times 1 -Exactly -ParameterFilter {
            $GpoId -eq [guid]'31B2F340-016D-11D2-945F-00C04FB984F9' -and
            $Sections['System Access']['MinimumPasswordLength'] -eq '14' -and
            $Sections['System Access']['PasswordComplexity'] -eq '1' -and
            $Sections['System Access']['LockoutBadCount'] -eq '10' -and
            $Sections['System Access']['LockoutDuration'] -eq '15' -and
            $Sections['System Access']['ResetLockoutCount'] -eq '15'
        }
        Should -Invoke New-ADFineGrainedPasswordPolicy -Times 1 -Exactly -ParameterFilter { $MinPasswordLength -eq 20 }
        Should -Invoke Add-ADFineGrainedPasswordPolicySubject -Times 1 -Exactly -ParameterFilter { $Subjects -eq 'GG-Tier0-Admins' }
    }
    It 'does not recreate or re-apply the Tier 0 policy when it is already in place' {
        Mock Get-ADFineGrainedPasswordPolicy { [pscustomobject]@{ AppliesTo = @('CN=GG-Tier0-Admins,OU=Tier0,OU=Admin,DC=corp,DC=internal') } }
        & (Join-Path $script:Harden 'Set-PasswordPolicy.ps1')
        Should -Invoke New-ADFineGrainedPasswordPolicy -Times 0 -Exactly
        Should -Invoke Add-ADFineGrainedPasswordPolicySubject -Times 0 -Exactly
    }
    It 'changes nothing with -WhatIf' {
        Mock Get-ADFineGrainedPasswordPolicy { $null }
        & (Join-Path $script:Harden 'Set-PasswordPolicy.ps1') -WhatIf
        Should -Invoke Set-LabGpoSecurityTemplate -Times 1 -Exactly -ParameterFilter { $WhatIf }
        Should -Invoke New-ADFineGrainedPasswordPolicy -Times 0 -Exactly
    }
}

Describe 'Disable-SpoolerOnDC' {
    BeforeEach {
        Mock Get-ADDomain -ModuleName LabCommon { $global:LabTestDomain }
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
        Mock Get-ADDomain -ModuleName LabCommon { $global:LabTestDomain }
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
        Mock Get-ADDomain -ModuleName LabCommon { $global:LabTestDomain }
        Mock Get-ADDomain { $global:LabTestDomain }
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
