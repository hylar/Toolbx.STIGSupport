<#
.SYNOPSIS
    This checks for compliancy on V-26539.

    The system must be configured to audit Detailed Tracking - Process Creation successes.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-26539"

# Initial Variables
$Results = @{
    VulnID   = "V-26539"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$line = $PreCheck.acctLogon -match "Credential Validation"
if ($line -like "*Success*") {
    $Results.Status = "NotAFinding"
    $Results.Details = "Detailed Tracking - Process Creation successes are being audited. See comments for details."
}
else {
    $Results.Status = "Open"
    $Results.Details = "Detailed Tracking - Process Creation succeses are NOT being audited. See comments for details."
}
$Results.Comments = "Auditpol.exe reports: `r`n$line"

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-26539 [$($Results.Status)]"

#Return results
return $Results
