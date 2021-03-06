<#
.SYNOPSIS
    This checks for compliancy on V-39332.

    The Active Directory Domain Controllers Organizational Unit (OU) object must have the proper access control permissions.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-39332"

# Initial Variables
$Results = @{
    VulnID   = "V-39332"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
if ($PreCheck.hostType -eq "Domain Controller") {
    Import-Module ActiveDirectory
    $domain = (Get-AdDomain).NetBIOSName
    $path = ('OU=Domain Controllers,'+(Get-AdDomain).distinguishedname)
    $acl = Get-Acl -Audit -Path ('AD:'+$path)
    $access = $acl.Access
    $fail = 0
    $failNames = @()
    foreach ($item in $access) {
        if (
            $item.IdentityReference -eq "NT AUTHORITY\SELF" -and
            $item.ActiveDirectoryRights -eq "ReadProperty, WriteProperty, ExtendedRight" -and
            $item.InheritanceType -eq "All" -and
            $item.IsInherited -eq $true
        ) {
            #Match default/expected entry
        }
        elseif (
            $item.IdentityReference -eq "NT AUTHORITY\SELF" -and
            ($item.ActiveDirectoryRights -eq "ReadProperty, WriteProperty, ExtendedRight" -or $item.ActiveDirectoryRights -eq "ReadProperty, WriteProperty" -or $item.ActiveDirectoryRights -eq "WriteProperty")
        ) {
            #Match default/expected entry
        }
        elseif (
            $item.IdentityReference -eq "NT AUTHORITY\SYSTEM" -and
            $item.ActiveDirectoryRights -eq "GenericAll" -and
            $item.InheritanceType -eq "None" -and
            $item.IsInherited -eq $false
        ) {
            #Match default/expected entry
        }
        elseif (
            $item.IdentityReference -eq "$domain\Domain Admins" -and
            $item.ActiveDirectoryRights -eq "CreateChild, Self, WriteProperty, ExtendedRight, GenericRead, WriteDacl, WriteOwner" -and
            $item.InheritanceType -eq "None" -and
            $item.IsInherited -eq $false
        ) {
            #Match default/expected entry
        }
        elseif (
            $item.IdentityReference -eq "BUILTIN\Pre-Windows 2000 Compatible Access" -and
            ($item.ActiveDirectoryRights -eq "GenericRead" -or $item.ActiveDirectoryRights -eq "ListChildren" -or $item.ActiveDirectoryRights -eq "ReadProperty")
        ) {
            #Match default/expected entry
        }
        elseif (
            $item.IdentityReference -eq "$domain\Enterprise Admins" -and
            $item.ActiveDirectoryRights -eq "GenericAll" -and
            $item.InheritanceType -eq "All" -and
            $item.IsInherited -eq $true
        ) {
            #Match default/expected entry
        }
        elseif (
            $item.IdentityReference -eq "BUILTIN\Administrators" -and
            $item.ActiveDirectoryRights -eq "CreateChild, Self, WriteProperty, ExtendedRight, Delete, GenericRead, WriteDacl, WriteOwner" -and
            $item.InheritanceType -eq "All" -and
            $item.IsInherited -eq $true
        ) {
            #Match default/expected entry
        }
        elseif (
            $item.IdentityReference -eq "NT AUTHORITY\Authenticated Users" -and
            ($item.ActiveDirectoryRights -eq "GenericRead" -or $item.ActiveDirectoryRights -eq "ReadProperty")
        ) {
            #Match default/expected entry
        }
        elseif (
            $item.IdentityReference -eq "NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS" -and
            ($item.ActiveDirectoryRights -eq "GenericRead" -or $item.ActiveDirectoryRights -eq "ReadProperty")
        ) {
            #Match default/expected entry
        }
        else{
            $fail = 1
            $failNames += $item.IdentityReference
        }
    }
    <# Possible exchange rights?
    "$domain\Exchange Trusted Subsystem"
    "$domain\Exchange Windows Permissions"
    "$domain\Exchange Servers"
    "$domain\Organization Management"
    #>
    if ($fail -eq 1) {
        $Results.Status = "Open"
        $Results.Details = "'Domain Controllers' organizational unit has unexpected rights; Please review! See comments for details."
        $Results.Comments = "-=Identities With Unexpected Rights=-`r`n`r`n"
        $Results.Comments += $failNames.Value | Select-Object -Unique | Out-String
        $Results.Comments += "`r`n-=All Rights=-"
        $Results.Comments += $access | Sort-Object -Property IdentityReference | Select-Object IdentityReference,ActiveDirectoryRights -Unique | Format-List | Out-String
    }
    else {
        $Results.Status = "NotAFinding"
        $Results.Details = "'Domain Controllers' organizational unit has only expected rights. See comments for details."
        $Results.Comments = "`r`n-=All Rights=-"
        $Results.Comments += $access | Sort-Object -Property IdentityReference | Select-Object IdentityReference,ActiveDirectoryRights -Unique | Format-List | Out-String
    }
}
else {
    $Results.Status = "Not_Applicable"
    $Results.Details = "Check only applies to Domain Controllers."
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-39332 [$($Results.Status)]"

#Return results
return $Results
