<#
.SYNOPSIS
    This checks for compliancy on V-39326.

    The Active Directory Domain object must be configured with proper audit settings.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-39326"

# Initial Variables
$Results = @{
    VulnID   = "V-39326"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
if ($PreCheck.hostType -eq "Domain Controller") {
    Import-Module ActiveDirectory
    $path = (Get-AdDomain).distinguishedname
    $acl = Get-Acl -Audit -Path ('AD:'+$path)
    $audit = $acl.Audit
    $fail = 0
    if ($audit.Count -eq 6) {
        foreach ($item in $audit) {
            if (
                $item.AuditFlags -eq "Failure" -and
                $item.IdentityReference -eq "Everyone" -and
                $item.ActiveDirectoryRights -eq "GenericAll" -and
                $item.InheritanceType -eq "None" -and
                $item.IsInherited -eq $false
            ) {
                #Match default/expected entry
            }
            elseif (
                $item.AuditFlags -eq "Success" -and
                $item.IdentityReference -eq "Everyone" -and
                $item.ActiveDirectoryRights -eq "WriteProperty" -and
                $item.InheritanceType -eq "All" -and
                $item.IsInherited -eq $false
            ) {
                #Match default/expected entry (two expected)
            }
            elseif (
                $item.AuditFlags -eq "Success" -and
                $item.IdentityReference -match "\\Domain Users" -and
                $item.ActiveDirectoryRights -eq "ExtendedRight" -and
                $item.InheritanceType -eq "None" -and
                $item.IsInherited -eq $false
            ) {
                #Match default/expected entry
            }
            elseif (
                $item.AuditFlags -eq "Success" -and
                $item.IdentityReference -eq "BUILTIN\Administrators" -and
                $item.ActiveDirectoryRights -eq "ExtendedRight" -and
                $item.InheritanceType -eq "None" -and
                $item.IsInherited -eq $false
            ) {
                #Match default/expected entry
            }
            elseif (
                $item.AuditFlags -eq "Success" -and
                $item.IdentityReference -eq "Everyone" -and
                $item.ActiveDirectoryRights -eq "WriteProperty, WriteDacl, WriteOwner" -and
                $item.InheritanceType -eq "None" -and
                $item.IsInherited -eq $false
            ) {
                #Match default/expected entry (two of these expected)
            }
            else{
                $fail = 1
            }
        }
    }
    else {
        $fail = 1
    }
    if ($fail -eq 1) {
        $Results.Status = "Open"
        $Results.Details = "Domain has unexpected audit rights; Please review! See comments for details."
        $Results.Comments = $audit | Select-Object AuditFlags,IdentityReference,ActiveDirectoryRights,InheritanceType | Format-List | Out-String
    }
    else {
        $Results.Status = "NotAFinding"
        $Results.Details = "Domain audit rights are as expected. See comments for details."
        $Results.Comments = $audit | Select-Object AuditFlags,IdentityReference,ActiveDirectoryRights,InheritanceType | Format-List | Out-String
    }
}
else {
    $Results.Status = "Not_Applicable"
    $Results.Details = "Check only applies to Domain Controllers."
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-39326 [$($Results.Status)]"

#Return results
return $Results
