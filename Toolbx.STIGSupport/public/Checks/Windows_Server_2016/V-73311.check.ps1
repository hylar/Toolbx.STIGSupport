<#
.SYNOPSIS
    This checks for compliancy on V-73311.

    Windows Server 2016 must have the number of allowed bad logon attempts configured to three or less.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73311"

# Initial Variables
$Results = @{
    VulnID   = "V-73311"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$raw = $PreCheck.secEdit -match "LockoutBadCount"
[int]$value = $raw -split '= ' | select -Last 1
if ($value -eq 1 -or $value -eq 2 -or $value -eq 3) {
    $Results.Status = "NotAFinding"
    $Results.Details = "Number of login attempts before lockout is set correctly. Secedit.exe reports: $raw"
}
else {
    $Results.Status = "Open"
    $Results.Details = "Number of login attempts before lockout is NOT set correctly. Secedit.exe reports: $raw"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73311 [$($Results.Status)]"

#Return results
return $Results
