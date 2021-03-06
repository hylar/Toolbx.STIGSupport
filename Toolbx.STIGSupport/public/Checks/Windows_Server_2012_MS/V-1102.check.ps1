<#
.SYNOPSIS
    This checks for compliancy on V-1102.

    The Act as part of the operating system user right must not be assigned to any groups or accounts.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-1102"

# Initial Variables
$Results = @{
    VulnID   = "V-1102"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$right = $PreCheck.userRights -match "SeTcbPrivilege"
if (!$right) {
    $Results.Details = "Unable to find entry in user rights!"
    $Results.Status = "Open"
}
else {
    [string]$value = $right.Accountlist
    if ($value.Length -eq 0) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Verified act as part of the operating system right is given to no user/group. See comments for details."
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Act as part of the operating system right contains one or more users/groups; Please review! See comments for details."
    }
    $Results.Comments = ($right | Out-String)
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-1102 [$($Results.Status)]"

#Return results
return $Results
