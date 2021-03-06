<#
.SYNOPSIS
    This checks for compliancy on V-73309.

    Windows 2016 account lockout duration must be configured to 15 minutes or greater.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73309"

# Initial Variables
$Results = @{
    VulnID   = "V-73309"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$raw = $PreCheck.secEdit -match "LockoutDuration"
[int]$value = $raw -split '= ' | select -Last 1
if ($value -ge 15 -or $value -eq 0) {
    $Results.Status = "NotAFinding"
    $Results.Details = "Lockout duration is set correctly. Secedit.exe reports: $raw"
}
else {
    $Results.Status = "Open"
    $Results.Details = "Lockout duration is NOT set correctly. Secedit.exe reports: $raw"
}


Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73309 [$($Results.Status)]"

#Return results
return $Results
