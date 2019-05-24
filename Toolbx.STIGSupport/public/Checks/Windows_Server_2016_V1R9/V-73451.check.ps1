<#
.SYNOPSIS
    This checks for compliancy on V-73451.

    Windows Server 2016 must be configured to audit Logon/Logoff - Logon successes.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73451"

# Initial Variables
$Results = @{
    VulnID   = "V-73451"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$line = $PreCheck.logonOff -match "Logon" | Select -Skip 1 -First 1
if ($line -like "*Success*") {
    $Results.Status = "NotAFinding"
}
else {
    $Results.Status = "Open"
}
$Results.Details = "Auditpol.exe reports: $line"

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73451 [$($Results.Status)]"

#Return results
return $Results
