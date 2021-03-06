<#
.SYNOPSIS
    This checks for compliancy on V-33666.

    The system must be configured to audit DS Access - Directory Service Changes failures.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-33666"

# Initial Variables
$Results = @{
    VulnID   = "V-33666"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
if ($PreCheck.hostType -eq "Domain Controller") {
    $line = $PreCheck.dsAccess -match "Directory Service Changes"
    if ($line -like "*Failure*") {
        $Results.Status = "NotAFinding"
        $Results.Details = "DS Access - Directory Service Changes failures are being audited. See comments for details."
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "DS Access - Directory Service Changes failures are NOT being audited! See comments for details."
    }
    $Results.Comments = "Auditpol.exe reports: `r`n$line"
}
else {
    $Results.Status = "Not_Applicable"
    $Results.Details = "Check only applies to Domain Controllers."
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-33666 [$($Results.Status)]"

#Return results
return $Results
