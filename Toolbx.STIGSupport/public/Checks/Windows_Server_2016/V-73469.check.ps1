<#
.SYNOPSIS
    This checks for compliancy on V-73469.

    Windows Server 2016 must be configured to audit Privilege Use - Sensitive Privilege Use successes.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73469"

# Initial Variables
$Results = @{
    VulnID   = "V-73469"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$line = $PreCheck.privUse -match "Sensitive Privilege Use" | Select -Skip 1
if ($line -like "*Success*") {
    $Results.Status = "NotAFinding"
    $Results.Details = "Privilege Use - Sensitive Privilege Use successes are being audited. Auditpol.exe reports: $line"
}
else {
    $Results.Status = "Open"
    $Results.Details = "Privilege Use - Sensitive Privilege Use successes are NOT being audited. Auditpol.exe reports: $line"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73469 [$($Results.Status)]"

#Return results
return $Results
