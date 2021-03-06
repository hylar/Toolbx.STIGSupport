<#
.SYNOPSIS
    This checks for compliancy on V-26542.

    The system must be configured to audit Logon/Logoff - Logon failures.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-26542"

# Initial Variables
$Results = @{
    VulnID   = "V-26542"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$line = $PreCheck.logonOff -match "Logon" | Select -Skip 1 -First 1
if ($line -like "*Failure*") {
    $Results.Status = "NotAFinding"
    $Results.Details = "Logon/Logoff - Logon failures are being audited. See comments for details."
}
else {
    $Results.Status = "Open"
    $Results.Details = "Logon/Logoff - Logon failures are NOT being audited. See comments for details."
}
$Results.Comments = "Auditpol.exe reports: `r`n$line"

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-26542 [$($Results.Status)]"

#Return results
return $Results
