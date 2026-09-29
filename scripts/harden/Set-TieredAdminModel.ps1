#Requires -Version 5.1
<#
.SYNOPSIS
    Fixes W07/W09: tiered administration and least-privilege helpdesk delegation.
.DESCRIPTION
    1. Creates tier admin groups GG-Tier0-Admins, GG-Tier1-Admins, GG-Tier2-Admins in the Admin tier OUs.
    2. Removes any permission GG-Helpdesk holds on the Admin OU (the path to Domain Admins found by BloodHound).
    3. Grants GG-Helpdesk "reset password" only on the Corp user OUs.
    4. Creates and links the GPO "LAB-Tier0-Logon-Restrictions" to the Corp computer OUs: Tier 0 accounts
       (Domain Admins, Enterprise Admins, GG-Tier0-Admins) are denied interactive, RDP, batch and service logon
       on workstations and member servers.
    Review with -WhatIf first and confirm with `gpresult /r` on ws01 after `gpupdate /force`: user-rights
    assignments are written to the GPO's security template (GptTmpl.inf) in SYSVOL.
    Idempotent and -WhatIf aware. Refuses to run outside corp.internal unless -Force.
#>
[CmdletBinding(SupportsShouldProcess)]
param([switch]$Force)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# Load the shared module once; re-importing would reset it (and any test mocks attached to it).
if (-not (Get-Module LabCommon)) { Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'LabCommon.psm1') }
Import-LabAdModule
Assert-LabDomain -Force:$Force
$domain = Get-ADDomain
$domainDn = $domain.DistinguishedName
$departments = 'Finance', 'Operations', 'Management'

# 1. Tier groups
foreach ($tier in 0, 1, 2) {
    $name = "GG-Tier$tier-Admins"
    if (-not (Get-ADGroup -Filter "Name -eq '$name'")) {
        if ($PSCmdlet.ShouldProcess($name, 'Create tier admin group')) {
            New-ADGroup -Name $name -GroupScope Global -GroupCategory Security -Path "OU=Tier$tier,OU=Admin,$domainDn"
            Write-LabChange -Action 'CreateGroup' -Target $name
        }
    }
}

# 2 and 3. Helpdesk delegation: nothing on the Admin OU, password reset on user OUs only
$helpdesk = Get-ADGroup -Identity 'GG-Helpdesk'
$helpdeskSid = [System.Security.Principal.SecurityIdentifier]$helpdesk.SID
$resetPasswordRight = [guid]'00299570-246d-11d0-a768-00aa006e0529'  # "Reset Password" extended right
$userClass = [guid]'bf967aba-0de6-11d0-a285-00aa003049e2'          # user objects

$adminOu = "AD:\OU=Admin,$domainDn"
$acl = Get-Acl -Path $adminOu
$helpdeskRules = @($acl.Access | Where-Object {
        $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) -eq $helpdeskSid -and -not $_.IsInherited
    })
if ($helpdeskRules -and $PSCmdlet.ShouldProcess('OU=Admin', 'Remove GG-Helpdesk permissions')) {
    foreach ($rule in $helpdeskRules) { [void]$acl.RemoveAccessRule($rule) }
    Set-Acl -Path $adminOu -AclObject $acl
    Write-LabChange -Action 'RemoveDelegation' -Target 'OU=Admin' -Detail "$($helpdeskRules.Count) rule(s) of GG-Helpdesk"
}

foreach ($dept in $departments) {
    $path = "AD:\OU=Users,OU=$dept,OU=Corp,$domainDn"
    $acl = Get-Acl -Path $path
    $present = @($acl.Access | Where-Object {
            $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) -eq $helpdeskSid -and
            $_.ObjectType -eq $resetPasswordRight
        })
    if (-not $present -and $PSCmdlet.ShouldProcess("OU=Users,OU=$dept", 'Delegate password reset to GG-Helpdesk')) {
        $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $helpdeskSid, 'ExtendedRight', 'Allow', $resetPasswordRight, 'Descendents', $userClass)
        $acl.AddAccessRule($rule)
        Set-Acl -Path $path -AclObject $acl
        Write-LabChange -Action 'DelegateReset' -Target "OU=Users,OU=$dept"
    }
}

# 4. Tier 0 logon restrictions on workstations and member servers
$gpoName = 'LAB-Tier0-Logon-Restrictions'
$tier0 = foreach ($groupName in 'Domain Admins', 'Enterprise Admins', 'GG-Tier0-Admins') {
    try {
        '*' + (Get-ADGroup -Identity $groupName).SID.Value
    } catch {
        # On a fresh domain the -WhatIf preview runs before step 1 has created GG-Tier0-Admins.
        if (-not $WhatIfPreference) { throw }
        Write-Warning "$groupName does not exist yet; the real run creates it first and includes it."
    }
}
$denyList = @($tier0) -join ','
$rights = [ordered]@{
    'Privilege Rights' = [ordered]@{
        SeDenyInteractiveLogonRight       = $denyList
        SeDenyRemoteInteractiveLogonRight = $denyList
        SeDenyBatchLogonRight             = $denyList
        SeDenyServiceLogonRight           = $denyList
    }
}

$gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
if (-not $gpo -and $PSCmdlet.ShouldProcess($gpoName, 'Create GPO')) {
    $gpo = New-GPO -Name $gpoName -Comment 'Deny Tier 0 logon on workstations and member servers - Lab 03 (W09)'
    Write-LabChange -Action 'CreateGpo' -Target $gpoName
}
if ($gpo) {
    # Merges into the GPO's GptTmpl.inf, bumps its version and registers the security extension.
    Set-LabGpoSecurityTemplate -GpoId $gpo.Id -Sections $rights -WhatIf:$WhatIfPreference
    foreach ($dept in $departments) {
        $ou = "OU=Computers,OU=$dept,OU=Corp,$domainDn"
        $linked = @((Get-GPInheritance -Target $ou).GpoLinks | Where-Object { $_.DisplayName -eq $gpoName })
        if (-not $linked -and $PSCmdlet.ShouldProcess($ou, "Link $gpoName")) {
            New-GPLink -Name $gpoName -Target $ou | Out-Null
            Write-LabChange -Action 'LinkGpo' -Target $ou -Detail $gpoName
        }
    }
}
