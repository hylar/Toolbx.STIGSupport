<#
.SYNOPSIS
    This checks for compliancy on V-36668.

    The system must be configured to audit Object Access - Removable Storage successes.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-36668"

# Initial Variables
$Results = @{
    VulnID   = "V-36668"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$line = $PreCheck.objAccess -match "Removable Storage"
if ($line -like "*Success*") {
    $Results.Status = "NotAFinding"
    $Results.Details = "Object Access - Removable Storage successes are being audited. See comments for details."
}
else {
    $Results.Status = "Open"
    $Results.Details = "Object Access - Removable Storage successes are NOT being audited! See comments for details."
}
$Results.Comments = "Auditpol.exe reports: `r`n$line"

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-36668 [$($Results.Status)]"

#Return results
return $Results
