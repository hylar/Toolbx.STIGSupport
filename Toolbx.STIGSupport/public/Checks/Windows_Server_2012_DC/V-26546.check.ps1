<#
.SYNOPSIS
    This checks for compliancy on V-26546.

    The system must be configured to audit Policy Change - Audit Policy Change successes.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-26546"

# Initial Variables
$Results = @{
    VulnID   = "V-26546"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$line = $PreCheck.polChange -match "Audit Policy Change"
if ($line -like "*Success*") {
    $Results.Status = "NotAFinding"
    $Results.Details = "Policy Change - Audit Policy Change successes are being audited. See comments for details."
}
else {
    $Results.Status = "Open"
    $Results.Details = "Policy Change - Audit Policy Change successes are NOT being audited! See comments for details."
}
$Results.Comments = "Auditpol.exe reports: `r`n$line"


Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-26546 [$($Results.Status)]"

#Return results
return $Results
