<#
.SYNOPSIS
    This checks for compliancy on V-73415.

    Windows Server 2016 must be configured to audit Account Logon - Credential Validation failures.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73415"

# Initial Variables
$Results = @{
    VulnID   = "V-73415"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$line = $PreCheck.acctLogon -match "Credential Validation"
if ($line -like "*Failure*") {
    $Results.Status = "NotAFinding"
    $Results.Details = "Account Logon - Credential Validation failures are being audited. Auditpol.exe reports: $line"
}
else {
    $Results.Status = "Open"
    $Results.Details = "Account Logon - Credential Validation failures are NOT being audited. Auditpol.exe reports: $line"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73415 [$($Results.Status)]"

#Return results
return $Results
