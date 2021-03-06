<#
.SYNOPSIS
    This checks for compliancy on V-90361.

    Windows 2016 must be configured to audit Object Access - Other Object Access Events failures.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-90361"

# Initial Variables
$Results = @{
    VulnID   = "V-90361"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$line = $objAccess -match "Other Object Access Events"
if ($line -like "*Failure*") {
    $Results.Status = "NotAFinding"
    $Results.Details = "Object Access - Other Object Access Events failures are being audited. Auditpol.exe reports: $line"
}
else {
    $Results.Status = "Open"
    $Results.Details = "Object Access - Other Object Access Events failures are NOT being audited. Auditpol.exe reports: $line"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-90361 [$($Results.Status)]"

#Return results
return $Results
