<#
.SYNOPSIS
    This checks for compliancy on V-73449.

    Windows Server 2016 must be configured to audit Logon/Logoff - Logoff successes.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73449"

# Initial Variables
$Results = @{
    VulnID   = "V-73449"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$line = $PreCheck.logonOff -match "Logoff" | Select -Skip 1 -First 1
if ($line -like "*Success*") {
    $Results.Status = "NotAFinding"
    $Results.Details = "Logon/Logoff - Logoff successes are being audited. Auditpol.exe reports: $line"
}
else {
    $Results.Status = "Open"
    $Results.Details = "Logon/Logoff - Logoff successes are NOT being audited. Auditpol.exe reports: $line"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73449 [$($Results.Status)]"


#Return results
return $Results
