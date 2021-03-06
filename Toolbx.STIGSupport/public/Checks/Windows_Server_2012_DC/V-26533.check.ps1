<#
.SYNOPSIS
    This checks for compliancy on V-26533.

    The system must be configured to audit Account Management - Other Account Management Events successes.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-26533"

# Initial Variables
$Results = @{
    VulnID   = "V-26533"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$line = $PreCheck.acctMgmt -match "Other Account Management Events"
if ($line -like "*Success*") {
    $Results.Status = "NotAFinding"
    $Results.Details = "Account Management - Other Account Management Events successes are being audited. See comments for details."
}
else {
    $Results.Status = "Open"
    $Results.Details = "Account Management - Other Account Management Events succeses are NOT being audited. See comments for details."
}
$Results.Comments = "Auditpol.exe reports: `r`n$line"

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-26533 [$($Results.Status)]"

#Return results
return $Results
