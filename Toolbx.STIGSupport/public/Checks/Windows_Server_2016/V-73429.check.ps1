<#
.SYNOPSIS
    This checks for compliancy on V-73429.

    Windows Server 2016 must be configured to audit Account Management - User Account Management failures.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73429"

# Initial Variables
$Results = @{
    VulnID   = "V-73429"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$line = $PreCheck.acctMgmt -match "User Account Management"
if ($line -like "*Failure*") {
    $Results.Status = "NotAFinding"
    $Results.Details = "Account Management - User Account Management failures are being audited. Auditpol.exe reports: $line"
}
else {
    $Results.Status = "Open"
    $Results.Details = "Account Management - User Account Management failures are NOT being audited. Auditpol.exe reports: $line"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73429 [$($Results.Status)]"

#Return results
return $Results
