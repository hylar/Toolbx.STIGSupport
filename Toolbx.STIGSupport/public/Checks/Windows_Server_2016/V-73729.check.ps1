<#
.SYNOPSIS
    This checks for compliancy on V-73729.

    The Access Credential Manager as a trusted caller user right must not be assigned to any groups or accounts.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73729"

# Initial Variables
$Results = @{
    VulnID   = "V-73729"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$right = $PreCheck.userRights -match "SeTrustedCredManAccessPrivilege"
if (!$right) {
    $Results.Details = "Unable to find entry in user rights!"
    $Results.Status = "Open"
}
else {
    if (($right.Accountlist).Length -eq 0) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Verified access Credential Manager as a trusted caller right is given to no user/group. See comments for details."
        $Results.Comments = ($right | Out-String)
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Access Credential Manager as a trusted caller right contains one or more users/groups; Please review! See comments for details."
        $Results.Comments = ($right | Out-String)
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73729 [$($Results.Status)]"

#Return results
return $Results
