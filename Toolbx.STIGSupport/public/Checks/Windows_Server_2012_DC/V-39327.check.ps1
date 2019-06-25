<#
.SYNOPSIS
    This checks for compliancy on V-39327.

    The Active Directory Infrastructure object must be configured with proper audit settings.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-39327"

# Initial Variables
$Results = @{
    VulnID   = "V-39327"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
if ($PreCheck.hostType -eq "Domain Controller") {
    Import-Module ActiveDirectory
    $path = ("CN=Infrastructure,"+(Get-AdDomain).distinguishedname)
    $acl = Get-Acl -Audit -Path ('AD:'+$path)
    $audit = $acl.Audit
    $fail = 0
    if ($audit.Count -eq 4) {
        foreach ($item in $audit) {
            if (
                $item.AuditFlags -eq "Success" -and
                $item.IdentityReference -eq "Everyone" -and
                $item.ActiveDirectoryRights -eq "WriteProperty, ExtendedRight" -and
                $item.InheritanceType -eq "None" -and
                $item.IsInherited -eq $false
            ) {
                #Match default/expected entry
            }
            elseif (
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
                $item.InheritanceType -eq "Descendents" -and
                $item.IsInherited -eq $true
            ) {
                #Match default/expected entry (two of these ones)
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
        $Results.Details = "Infrastructure object has unexpected audit rights; Please review! See comments for details."
        $Results.Comments = $audit | Select-Object AuditFlags,IdentityReference,ActiveDirectoryRights,InheritanceType | Format-List | Out-String
    }
    else {
        $Results.Status = "NotAFinding"
        $Results.Details = "Infrastructure object has only expected audit rights. See comments for details."
        $Results.Comments = $audit | Select-Object AuditFlags,IdentityReference,ActiveDirectoryRights,InheritanceType | Format-List | Out-String
    }
}
else {
    $Results.Status = "Not_Applicable"
    $Results.Details = "Check only applies to Domain Controllers."
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-39327 [$($Results.Status)]"

#Return results
return $Results
