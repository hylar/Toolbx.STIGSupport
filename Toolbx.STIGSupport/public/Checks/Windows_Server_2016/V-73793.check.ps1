<#
.SYNOPSIS
    This checks for compliancy on V-73793.

    The Manage auditing and security log user right must only be assigned to the Administrators group.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73793"

# Initial Variables
$Results = @{
    VulnID   = "V-73793"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$right = $PreCheck.userRights -match "SeSecurityPrivilege"
if (!$right) {
    $Results.Details = "Unable to find entry in user rights!"
    $Results.Status = "Open"
}
else {
    [string]$value = $right.Accountlist
    if (($value -replace "Administrators", "" -replace " ", "").Length -eq 0) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Audit and security log managment rights only includes Administrators. See comments for details."
        $Results.Comments = ($right | Out-String)
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Audit and security log managment rights have additional members! See comments for details."
        $Results.Comments = ($right | Out-String)
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73793 [$($Results.Status)]"

#Return results
return $Results
