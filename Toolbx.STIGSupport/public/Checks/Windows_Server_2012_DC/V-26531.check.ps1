<#
.SYNOPSIS
    This checks for compliancy on V-26531.

    Windows Server 2012/2012 R2 domain controllers must be configured to audit Account Management - Computer Account Management successes.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-26531"

# Initial Variables
$Results = @{
    VulnID   = "V-26531"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
if ($PreCheck.hostType -eq "Domain Controller") {
    $line = $PreCheck.acctMgmt -match "Computer Account Management"
    if ($line -like "*Success*") {
        $Results.Status = "NotAFinding"
        $Results.Details = "Account Management - Computer Account Management successes are being audited. See comments for details."
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Account Management - Computer Account Management successes are NOT being audited. See comments for details."
    }
    $Results.Comments = "Auditpol.exe reports: `r`n$line"
}
else {
    $Results.Status = "Not_Applicable"
    $Results.Details = "Check only applies to Domain Controllers."
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-26531 [$($Results.Status)]"

#Return results
return $Results
