<#
.SYNOPSIS
    This checks for compliancy on V-73809.

    Windows Server 2016 built-in guest account must be disabled.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73809"

# Initial Variables
$Results = @{
    VulnID   = "V-73809"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$raw = $PreCheck.secEdit -match "EnableGuestAccount"
[int]$value = $raw -split '= ' | select -Last 1
if ($value -eq 0) {
    $Results.Status = "NotAFinding"
    $Results.Details = "Guest account is disabled. Secedit.exe reports: $raw"
}
else {
    $Results.Status = "Open"
    $Results.Details = "Guest account is NOT disabled! Secedit.exe reports: $raw"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73809 [$($Results.Status)]"

#Return results
return $Results
