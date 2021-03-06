<#
.SYNOPSIS
    This checks for compliancy on V-73479.

    Windows Server 2016 must be configured to audit System - Other System Events failures.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73479"

# Initial Variables
$Results = @{
    VulnID   = "V-73479"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$line = $PreCheck.system -match "Other System Events"
if ($line -like "*Failure*") {
    $Results.Status = "NotAFinding"
    $Results.Details = "Other System Events failures are being audited. Auditpol.exe reports: $line"
}
else {
    $Results.Status = "Open"
    $Results.Details = "Other System Events failures are NOT being audited. Auditpol.exe reports: $line"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73479 [$($Results.Status)]"

#Return results
return $Results
