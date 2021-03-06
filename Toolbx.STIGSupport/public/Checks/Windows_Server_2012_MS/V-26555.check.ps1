<#
.SYNOPSIS
    This checks for compliancy on V-26555.

    The system must be configured to audit System - Security System Extension successes.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-26555"

# Initial Variables
$Results = @{
    VulnID   = "V-26555"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$line = $PreCheck.system -match "Security System Extension"
if ($line -like "*Success*") {
    $Results.Status = "NotAFinding"
    $Results.Details = "System - Security System Extension successes are being audited. See comments for details."
}
else {
    $Results.Status = "Open"
    $Results.Details = "System - Security System Extension successes are NOT being audited! See comments for details."
}
$Results.Comments = "Auditpol.exe reports: `r`n$line"

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-26555 [$($Results.Status)]"

#Return results
return $Results
