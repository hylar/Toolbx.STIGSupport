<#
.SYNOPSIS
    This checks for compliancy on V-26557.

    The system must be configured to audit System - System Integrity successes.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-26557"

# Initial Variables
$Results = @{
    VulnID   = "V-26557"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$line = $PreCheck.system -match "System Integrity"
if ($line -like "*Success*") {
    $Results.Status = "NotAFinding"
    $Results.Details = "System - System Integrity successes are being audited. See comments for details."
}
else {
    $Results.Status = "Open"
    $Results.Details = "System - System Integrity successes are NOT being audited! See comments for details."
}
$Results.Comments = "Auditpol.exe reports: `r`n$line"

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-26557 [$($Results.Status)]"

#Return results
return $Results
