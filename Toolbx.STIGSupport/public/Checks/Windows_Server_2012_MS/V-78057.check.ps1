<#
.SYNOPSIS
    This checks for compliancy on V-78057.

    Windows Server 2012/2012 R2 must be configured to audit Logon/Logoff - Account Lockout successes.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-78057"

# Initial Variables
$Results = @{
    VulnID   = "V-78057"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$line = $PreCheck.logonOff -match "Account Lockout"
if ($line -like "*Success*") {
    $Results.Status = "NotAFinding"
    $Results.Details = "Logon/Logoff - Account Lockout successes are being audited. See comments for details."
}
else {
    $Results.Status = "Open"
    $Results.Details = "Logon/Logoff - Account Lockout successes are NOT being audited! See comments for details."
}
$Results.Comments = "Auditpol.exe reports: `r`n$line"

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-78057 [$($Results.Status)]"

#Return results
return $Results
