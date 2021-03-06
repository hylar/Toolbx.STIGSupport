<#
.SYNOPSIS
    This checks for compliancy on V-73433.

    Windows Server 2016 must be configured to audit Detailed Tracking - Process Creation successes.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73433"

# Initial Variables
$Results = @{
    VulnID   = "V-73433"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$line = $PreCheck.detTrack -match "Process Creation"
if ($line -like "*Success*") {
    $Results.Status = "NotAFinding"
    $Results.Details = "Detailed Tracking - Process Creation successes are being audited. Auditpol.exe reports: $line"
}
else {
    $Results.Status = "Open"
    $Results.Details = "Detailed Tracking - Process Creation successes are NOT being audited. Auditpol.exe reports: $line"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73433 [$($Results.Status)]"

#Return results
return $Results
