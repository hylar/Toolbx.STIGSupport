<#
.SYNOPSIS
    This checks for compliancy on V-73427.

    Windows Server 2016 must be configured to audit Account Management - User Account Management successes.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73427"

# Initial Variables
$Results = @{
    VulnID   = "V-73427"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$line = $PreCheck.acctMgmt -match "User Account Management"
if ($line -like "*Success*") {
    $Results.Status = "NotAFinding"
    $Results.Details = "Account Management - User Account Management successes are being audited. Auditpol.exe reports: $line"
}
else {
    $Results.Status = "Open"
    $Results.Details = "Account Management - User Account Management successes are NOT being audited. Auditpol.exe reports: $line"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73427 [$($Results.Status)]"

#Return results
return $Results
