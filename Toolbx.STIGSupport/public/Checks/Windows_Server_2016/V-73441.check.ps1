<#
.SYNOPSIS
    This checks for compliancy on V-73441.

    Windows Server 2016 must be configured to audit DS Access - Directory Service Changes failures.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73441"

# Initial Variables
$Results = @{
    VulnID   = "V-73441"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
if ($PreCheck.HostType -eq "Domain Controller") {
    $line = $dsAccess -match "Directory Service Changes"
    if ($line -like "*Failure*") {
        $Results.Status = "NotAFinding"
        $Results.Details = "DS Access - Directory Service Changes failures are being audited. Auditpol.exe reports: $line"
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "DS Access - Directory Service Changes failures are NOT being audited. Auditpol.exe reports: $line"
    }
}
else {
    $Results.Details = "Check is only applicable to Domain Controllers."
    $Results.Status = "Not_Applicable"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73441 [$($Results.Status)]"

#Return results
return $Results
