<#
.SYNOPSIS
    This checks for compliancy on V-39333.

    Domain created Active Directory Organizational Unit (OU) objects must have proper access control permissions.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-39333"

# Initial Variables
$Results = @{
    VulnID   = "V-39333"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
if ($PreCheck.hostType -eq "Domain Controller") {
    Import-Module ActiveDirectory
    $OUs = (Get-ADOrganizationalUnit -SearchBase (Get-AdDomain).distinguishedname -Filter {(ObjectClass -eq "organizationalUnit") -and (Name -ne "Domain Controllers")} -SearchScope 1).DistinguishedName
    $domain = (Get-AdDomain).NetBIOSName
    $fail = 0
    $failNames = @()
    foreach ($ou in $OUs) {
        $acl = Get-Acl -Audit -Path ('AD:'+$ou)
        $access = $acl.Access
        foreach ($item in $access) {
            if (
                $item.IdentityReference -eq "NT AUTHORITY\SELF" -and
                ($item.ActiveDirectoryRights -eq "ReadProperty, WriteProperty, ExtendedRight" -or $item.ActiveDirectoryRights -eq "ReadProperty, WriteProperty" -or $item.ActiveDirectoryRights -eq "WriteProperty")
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
                $item.IdentityReference -eq "NT AUTHORITY\SYSTEM" -and
                $item.ActiveDirectoryRights -eq "GenericAll"
            ) {
                #Match default/expected entry
            }
            elseif (
                $item.IdentityReference -eq "$domain\Domain Admins" -and
                $item.ActiveDirectoryRights -eq "GenericAll"
            ) {
                #Match default/expected entry
            }
            elseif (
                $item.IdentityReference -eq "$domain\Enterprise Admins" -and
                $item.ActiveDirectoryRights -eq "GenericAll"
            ) {
                #Match default/expected entry
            }
            elseif (
                $item.IdentityReference -eq "BUILTIN\Administrators" -and
                $item.ActiveDirectoryRights -eq "CreateChild, Self, WriteProperty, ExtendedRight, Delete, GenericRead, WriteDacl, WriteOwner"
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
            $item.IdentityReference -eq "NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS" -and
            ($item.ActiveDirectoryRights -eq "GenericRead" -or $item.ActiveDirectoryRights -eq "ReadProperty")
            ) {
                #Match default/expected entry
            }
            else{
                $fail = 1
                $failNames += ("$ou | "+$item.IdentityReference)
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
            $Results.Details = "Some organizational units have unexpected rights; Please review! See comments for details."
            $Results.Comments = "-=OU | Identities With Unexpected Rights=-`r`n`r`n"
            $Results.Comments += $failNames | Select-Object -Unique | Out-String
            $Results.Comments += "`r`n-=OUs Analyzed=-`r`n"
            $Results.Comments += $OUs | Out-String
        }
        else {
            $Results.Status = "NotAFinding"
            $Results.Details = "All examined organizational units have only expected rights. See comments for details."
            $Results.Comments += "-=OUs Analyzed=-"
            $Results.Comments += $OUs | Out-String
        }
    }
}
else {
    $Results.Status = "Not_Applicable"
    $Results.Details = "Check only applies to Domain Controllers."
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-39333 [$($Results.Status)]"

#Return results
return $Results
