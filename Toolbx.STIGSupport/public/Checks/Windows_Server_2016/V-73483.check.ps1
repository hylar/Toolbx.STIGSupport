<#
.SYNOPSIS
    This checks for compliancy on V-73483.

    Windows Server 2016 must be configured to audit System - Security System Extension successes.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73483"

# Initial Variables
$Results = @{
    VulnID   = "V-73483"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$line = $PreCheck.system -match "Security System Extension"
if ($line -like "*Success*") {
    $Results.Status = "NotAFinding"
    $Results.Details = "System - Security System Extension successes are being audited. Auditpol.exe reports: $line"
}
else {
    $Results.Status = "Open"
    $Results.Details = "System - Security System Extension successes are NOT being audited. Auditpol.exe reports: $line"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73483 [$($Results.Status)]"

#Return results
return $Results
