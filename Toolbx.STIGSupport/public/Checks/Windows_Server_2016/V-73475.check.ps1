<#
.SYNOPSIS
    This checks for compliancy on V-73475.

    Windows Server 2016 must be configured to audit System - IPsec Driver failures.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73475"

# Initial Variables
$Results = @{
    VulnID   = "V-73475"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$line = $PreCheck.system -match "IPsec Driver"
if ($line -like "*Failure*") {
    $Results.Status = "NotAFinding"
    $Results.Details = "System - IPsec Driver failures are being audited. Auditpol.exe reports: $line"
}
else {
    $Results.Status = "Open"
    $Results.Details = "System - IPsec Driver failures are NOT being audited. Auditpol.exe reports: $line"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73475 [$($Results.Status)]"

#Return results
return $Results
