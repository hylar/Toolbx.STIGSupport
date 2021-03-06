<#
.SYNOPSIS
    This checks for compliancy on V-73461.

    Windows Server 2016 must be configured to audit Policy Change - Audit Policy Change successes.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73461"

# Initial Variables
$Results = @{
    VulnID   = "V-73461"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$line = $PreCheck.polChange -match "Audit Policy Change"
if ($line -like "*Success*") {
    $Results.Status = "NotAFinding"
    $Results.Details = "Policy Change - Audit Policy Change successes are being audited. Auditpol.exe reports: $line"
}
else {
    $Results.Status = "Open"
    $Results.Details = "Policy Change - Audit Policy Change successes are NOT being audited. Auditpol.exe reports: $line"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73461 [$($Results.Status)]"

#Return results
return $Results
