<#
.SYNOPSIS
    This checks for compliancy on V-26487.

    Unauthorized accounts must not have the Enable computer and user accounts to be trusted for delegation user right on member servers.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-26487"

# Initial Variables
$Results = @{
    VulnID   = "V-26487"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$right = $PreCheck.userRights -match "SeEnableDelegationPrivilege"
if (!$right) {
    $Results.Details = "Unable to find entry in user rights!"
    $Results.Status = "Open"
}
else {
    [string]$value = $right.Accountlist
    if (($value -replace " ", "").Length -eq 0) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Verified enable computer and user accounts to be trusted for delegation right is given to no user/group. See comments for details."
        $Results.Comments = ($right | Out-String)
    }
    $Results.Comments = ($right | Out-String)
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Enable computer and user accounts to be trusted for delegation right contains some users/groups; Please review! See comments for details."
        $Results.Comments = ($right | Out-String)
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-26487 [$($Results.Status)]"

#Return results
return $Results
