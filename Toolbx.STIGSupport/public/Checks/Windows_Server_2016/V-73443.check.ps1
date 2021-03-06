<#
.SYNOPSIS
    This checks for compliancy on V-73443.

    Windows Server 2016 must be configured to audit Logon/Logoff - Account Lockout successes.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73443"

# Initial Variables
$Results = @{
    VulnID   = "V-73443"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$line = $PreCheck.logonOff -match "Account Lockout"
if ($line -like "*Success*") {
    $Results.Status = "NotAFinding"
    $Results.Details = "Logon/Logoff - Account Lockout successes are being audited. Auditpol.exe reports: $line"
}
else {
    $Results.Status = "Open"
    $Results.Details = "Logon/Logoff - Account Lockout successes are NOT being audited. Auditpol.exe reports: $line"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73443 [$($Results.Status)]"

#Return results
return $Results
