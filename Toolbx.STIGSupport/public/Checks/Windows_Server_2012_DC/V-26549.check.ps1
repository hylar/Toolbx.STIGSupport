<#
.SYNOPSIS
    This checks for compliancy on V-26549.

    The system must be configured to audit Privilege Use - Sensitive Privilege Use successes.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-26549"

# Initial Variables
$Results = @{
    VulnID   = "V-26549"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$line = $PreCheck.privUse -match "Sensitive Privilege Use" | Select-Object -Last 1
if ($line -like "*Success*") {
    $Results.Status = "NotAFinding"
    $Results.Details = "Privilege Use - Sensitive Privilege successes are being audited. See comments for details."
}
else {
    $Results.Status = "Open"
    $Results.Details = "Privilege Use - Sensitive Privilege successes are NOT being audited! See comments for details."
}
$Results.Comments = "Auditpol.exe reports: `r`n$line"

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-26549 [$($Results.Status)]"

#Return results
return $Results
