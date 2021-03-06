<#
.SYNOPSIS
    This checks for compliancy on V-26550.

    The system must be configured to audit Privilege Use - Sensitive Privilege Use failures.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-26550"

# Initial Variables
$Results = @{
    VulnID   = "V-26550"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$line = $PreCheck.privUse -match "Sensitive Privilege Use" | Select-Object -Last 1
if ($line -like "*Failure*") {
    $Results.Status = "NotAFinding"
    $Results.Details = "Privilege Use - Sensitive Privilege failures are being audited. See comments for details."
}
else {
    $Results.Status = "Open"
    $Results.Details = "Privilege Use - Sensitive Privilege failures are NOT being audited! See comments for details."
}
$Results.Comments = "Auditpol.exe reports: `r`n$line"

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-26550 [$($Results.Status)]"

#Return results
return $Results
