<#
.SYNOPSIS
    This checks for compliancy on V-73791.

    The Lock pages in memory user right must not be assigned to any groups or accounts.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73791"

# Initial Variables
$Results = @{
    VulnID   = "V-73791"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$right = $PreCheck.userRights -match "SeLockMemoryPrivilege"
if (!$right) {
    $Results.Details = "Unable to find entry in user rights!"
    $Results.Status = "Open"
}
else {
    [string]$value = $right.Accountlist
    if (($value).Length -eq 0) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Lock pages in memory rights are granted to no users/groups. See comments for details."
        $Results.Comments = ($right | Out-String)
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Lock pages in memory rights have been delegated! See comments for details."
        $Results.Comments = ($right | Out-String)
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73791 [$($Results.Status)]"

#Return results
return $Results
