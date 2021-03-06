<#
.SYNOPSIS
    This checks for compliancy on V-73313.

    Windows Server 2016 must have the period of time before the bad logon counter is reset configured to 15 minutes or greater.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73313"

# Initial Variables
$Results = @{
    VulnID   = "V-73313"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$raw = $PreCheck.secEdit -match "ResetLockoutCount"
[int]$value = $raw -split '= ' | select -Last 1
if ($value -ge 15) {
    $Results.Status = "NotAFinding"
    $Results.Details = "Lockout reset time period is set correctly. Secedit.exe reports: $raw"
}
else {
    $Results.Status = "Open"
    $Results.Details = "Lockout reset time period is NOT set correctly. Secedit.exe reports: $raw"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73313 [$($Results.Status)]"

#Return results
return $Results
