<#
.SYNOPSIS
    This checks for compliancy on V-26552.

    The system must be configured to audit System - IPsec Driver failures.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-26552"

# Initial Variables
$Results = @{
    VulnID   = "V-26552"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$line = $PreCheck.system -match "IPsec Driver"
if ($line -like "*Failure*") {
    $Results.Status = "NotAFinding"
    $Results.Details = "System - IPsec Driver failures are being audited. See comments for details."
}
else {
    $Results.Status = "Open"
    $Results.Details = "System - IPsec Driver failures are NOT being audited! See comments for details."
}
$Results.Comments = "Auditpol.exe reports: `r`n$line"

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-26552 [$($Results.Status)]"

#Return results
return $Results
