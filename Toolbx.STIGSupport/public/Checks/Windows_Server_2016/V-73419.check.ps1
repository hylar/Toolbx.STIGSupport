<#
.SYNOPSIS
    This checks for compliancy on V-73419.

    Windows Server 2016 must be configured to audit Account Management - Other Account Management Events successes.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73419"

# Initial Variables
$Results = @{
    VulnID   = "V-73419"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$line = $PreCheck.acctMgmt -match "Other Account Management Events"
if ($line -like "*Success*") {
    $Results.Status = "NotAFinding"
    $Results.Details = "Account Management - Other Account Management Events successes are being audited. Auditpol.exe reports: $line"
}
else {
    $Results.Status = "Open"
    $Results.Details = "Account Management - Other Account Management Events successes are NOT being audited. Auditpol.exe reports: $line"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73419 [$($Results.Status)]"

#Return results
return $Results
