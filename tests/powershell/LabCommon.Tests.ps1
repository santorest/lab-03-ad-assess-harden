BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
}

Describe 'Assert-LabDomain' {
    It 'passes on the lab domain' {
        Mock Get-ADDomain -ModuleName LabCommon { [pscustomobject]@{ DNSRoot = 'corp.internal' } }
        { Assert-LabDomain } | Should -Not -Throw
    }

    It 'refuses look-alike or other domains: <_>' -ForEach @('corp.internal.evil', 'xcorp.internal', 'contoso.com') {
        $name = $_
        Mock Get-ADDomain -ModuleName LabCommon { [pscustomobject]@{ DNSRoot = $name } }
        { Assert-LabDomain } | Should -Throw '*only runs against the lab domain*'
    }

    It 'allows another domain only with -Force' {
        Mock Get-ADDomain -ModuleName LabCommon { [pscustomobject]@{ DNSRoot = 'contoso.com' } }
        { Assert-LabDomain -Force -WarningAction SilentlyContinue } | Should -Not -Throw
    }
}

Describe 'Write-LabChange' {
    It 'appends a line to logs/changes.log' {
        Mock Add-Content -ModuleName LabCommon {}
        Write-LabChange -Action 'Test' -Target 'X' -Detail 'y'
        Should -Invoke Add-Content -ModuleName LabCommon -Times 1 -ParameterFilter { $Value -like '* Test X y' }
    }
}

Describe 'Merge-LabInfTemplate' {
    It 'builds a template with the Unicode and Version headers from nothing' {
        $out = Merge-LabInfTemplate -Current '' -Sections ([ordered]@{ 'Privilege Rights' = [ordered]@{ SeDenyBatchLogonRight = '*S-1-5-32-544' } })
        $out | Should -Match '(?m)^\[Unicode\]\r?\nUnicode=yes'
        $out | Should -Match '(?m)^signature="\$CHICAGO\$"'
        $out | Should -Match '(?m)^\[Privilege Rights\]\r?\nSeDenyBatchLogonRight = \*S-1-5-32-544'
    }

    It 'keeps existing sections and keys and overrides only the given keys' {
        $current = "[Unicode]`r`nUnicode=yes`r`n[System Access]`r`nMinimumPasswordLength = 7`r`nPasswordComplexity = 1`r`n[Privilege Rights]`r`nSeBackupPrivilege = *S-1-5-32-551"
        $out = Merge-LabInfTemplate -Current $current -Sections ([ordered]@{ 'System Access' = [ordered]@{ MinimumPasswordLength = '14' } })
        $out | Should -Match 'MinimumPasswordLength = 14'
        $out | Should -Not -Match 'MinimumPasswordLength = 7'
        $out | Should -Match 'PasswordComplexity = 1'
        $out | Should -Match 'SeBackupPrivilege = \*S-1-5-32-551'
    }
}

Describe 'Merge-LabGpoExtensionList' {
    It 'adds a pair to an empty value' {
        Merge-LabGpoExtensionList -Current $null -Add '[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]' |
            Should -Be '[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]'
    }

    It 'keeps existing extensions, does not duplicate, and sorts by extension GUID' {
        $registry = '[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]'
        $security = '[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]'
        $merged = Merge-LabGpoExtensionList -Current $security -Add $registry
        $merged | Should -Be ($registry + $security)
        Merge-LabGpoExtensionList -Current $merged -Add $security | Should -Be $merged
    }
}

Describe 'Set-LabGpoSecurityTemplate' {
    BeforeEach {
        $script:Id = [guid]'11111111-2222-3333-4444-555555555555'
        $script:Root = Join-Path $TestDrive "Policies-$([guid]::NewGuid())"
        $script:GpoDir = Join-Path $script:Root "{$script:Id}"
        $script:Inf = Join-Path $script:GpoDir 'Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf'
        New-Item -ItemType Directory -Path $script:GpoDir -Force | Out-Null
        Set-Content -Path (Join-Path $script:GpoDir 'GPT.INI') -Value "[General]`r`ndisplayName=Lab GPO`r`nVersion=4" -Encoding Ascii
        Mock Get-ADDomain -ModuleName LabCommon { [pscustomobject]@{ DNSRoot = 'corp.internal'; DistinguishedName = 'DC=corp,DC=internal' } }
        Mock Get-ADObject -ModuleName LabCommon {
            [pscustomobject]@{ versionNumber = 4; gPCMachineExtensionNames = '[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]' }
        }
        Mock Set-ADObject -ModuleName LabCommon {}
        Mock Write-LabChange -ModuleName LabCommon {}
        $script:Sections = [ordered]@{ 'Privilege Rights' = [ordered]@{ SeDenyBatchLogonRight = '*S-1-5-32-544' } }
    }

    It 'writes GptTmpl.inf under Machine and bumps Version in GPT.INI at the GPO root' {
        Set-LabGpoSecurityTemplate -GpoId $script:Id -Sections $script:Sections -PolicyRoot $script:Root
        Get-Content -Path $script:Inf -Raw -Encoding Unicode | Should -Match 'SeDenyBatchLogonRight = \*S-1-5-32-544'
        $ini = Get-Content -Path (Join-Path $script:GpoDir 'GPT.INI') -Raw
        $ini | Should -Match 'Version=5'
        $ini | Should -Match 'displayName=Lab GPO'
        Join-Path $script:GpoDir 'Machine\GPT.INI' | Should -Not -Exist
    }

    It 'merges the security extension into the existing extension names' {
        Set-LabGpoSecurityTemplate -GpoId $script:Id -Sections $script:Sections -PolicyRoot $script:Root
        Should -Invoke Set-ADObject -ModuleName LabCommon -Times 1 -Exactly -ParameterFilter {
            $Replace.gPCMachineExtensionNames -like '*35378EAC*' -and $Replace.gPCMachineExtensionNames -like '*827D319E*' -and
            $Replace.versionNumber -eq 5
        }
    }

    It 'keeps settings already in the template' {
        New-Item -ItemType Directory -Path (Split-Path $script:Inf) -Force | Out-Null
        Set-Content -Path $script:Inf -Value "[Unicode]`r`nUnicode=yes`r`n[System Access]`r`nMinimumPasswordLength = 14" -Encoding Unicode
        Set-LabGpoSecurityTemplate -GpoId $script:Id -Sections $script:Sections -PolicyRoot $script:Root
        $inf = Get-Content -Path $script:Inf -Raw -Encoding Unicode
        $inf | Should -Match 'MinimumPasswordLength = 14'
        $inf | Should -Match 'SeDenyBatchLogonRight'
    }

    It 'does nothing when the template already holds the settings' {
        Set-LabGpoSecurityTemplate -GpoId $script:Id -Sections $script:Sections -PolicyRoot $script:Root
        Set-LabGpoSecurityTemplate -GpoId $script:Id -Sections $script:Sections -PolicyRoot $script:Root
        Should -Invoke Set-ADObject -ModuleName LabCommon -Times 1 -Exactly
    }

    It 'changes nothing with -WhatIf' {
        Set-LabGpoSecurityTemplate -GpoId $script:Id -Sections $script:Sections -PolicyRoot $script:Root -WhatIf
        $script:Inf | Should -Not -Exist
        Should -Invoke Set-ADObject -ModuleName LabCommon -Times 0 -Exactly
    }
}

Describe 'Test stand-ins' {
    It 'cover every AD, Group Policy, LAPS and KDS command the scripts call (tests never reach a real domain)' {
        $scripts = Get-ChildItem -Path $script:ScriptsDir -Recurse -Include *.ps1, *.psm1
        $used = foreach ($file in $scripts) {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$null, [ref]$null)
            $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true) |
                ForEach-Object { $_.GetCommandName() } | Where-Object { $_ -match '^[A-Za-z]+-(AD|GP|Laps|Kds)' }
        }
        $missing = @($used | Sort-Object -Unique | Where-Object { -not (Get-Command -Name $_ -CommandType Function -ErrorAction SilentlyContinue) })
        $missing | Should -BeNullOrEmpty
    }
}

Describe 'Set-LabGpoRegistryPolicy' {
    BeforeEach {
        Mock Get-GPO -ModuleName LabCommon { [pscustomobject]@{ DisplayName = 'LAB-Test' } }
        Mock Get-GPRegistryValue -ModuleName LabCommon { $null }
        Mock Set-GPRegistryValue -ModuleName LabCommon {}
        Mock Get-GPInheritance -ModuleName LabCommon { [pscustomobject]@{ GpoLinks = @([pscustomobject]@{ DisplayName = 'LAB-Test' }) } }
        Mock Write-LabChange -ModuleName LabCommon {}
    }

    It 'writes DWORD values by default and string values when the setting says Type = String' {
        $settings = @(
            @{ Key = 'HKLM\Software\Test'; ValueName = 'Number'; Value = 5 }
            @{ Key = 'HKLM\Software\Test'; ValueName = 'Text'; Value = 'S-1-5-21-1-2-3-1105'; Type = 'String' }
        )
        Set-LabGpoRegistryPolicy -GpoName 'LAB-Test' -Comment 'x' -Settings $settings -LinkTargets 'OU=A'
        Should -Invoke Set-GPRegistryValue -ModuleName LabCommon -Times 1 -Exactly -ParameterFilter { $ValueName -eq 'Number' -and $Type -eq 'DWord' }
        Should -Invoke Set-GPRegistryValue -ModuleName LabCommon -Times 1 -Exactly -ParameterFilter {
            $ValueName -eq 'Text' -and $Type -eq 'String' -and $Value -eq 'S-1-5-21-1-2-3-1105'
        }
    }
}
