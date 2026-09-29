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
