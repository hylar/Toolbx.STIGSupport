<#
.SYNOPSIS
    This checks for compliancy on V-73751.

    The Create permanent shared objects user right must not be assigned to any groups or accounts.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73751"

# Initial Variables
$Results = @{
    VulnID   = "V-73751"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$right = $PreCheck.userRights -match "SeCreatePermanentPrivilege"
if (!$right) {
    $Results.Details = "Unable to find entry in user rights!"
    $Results.Status = "Open"
}
else {
    [string]$value = $right.Accountlist
    if (($value).Length -eq 0) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Verified create permanent shared object right is given to no user/group. See comments for details."
        $Results.Comments = ($right | Out-String)
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Create permanent shared object right contains one or more users/groups, please review! See comments for details."
        $Results.Comments = ($right | Out-String)
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73751 [$($Results.Status)]"

#Return results
return $Results
