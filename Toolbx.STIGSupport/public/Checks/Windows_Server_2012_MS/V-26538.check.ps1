<#
.SYNOPSIS
    This checks for compliancy on V-26538.

    The system must be configured to audit Account Management - User Account Management failures.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-26538"

# Initial Variables
$Results = @{
    VulnID   = "V-26538"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$line = $PreCheck.acctMgmt -match "User Account Management"
if ($line -like "*Failure*") {
    $Results.Status = "NotAFinding"
    $Results.Details = "Account Management - User Account Management failures are being audited. See comments for details."
}
else {
    $Results.Status = "Open"
    $Results.Details = "Account Management - User Account Management failures are NOT being audited. See comments for details."
}
$Results.Comments = "Auditpol.exe reports: `r`n$line"

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-26538 [$($Results.Status)]"

#Return results
return $Results
