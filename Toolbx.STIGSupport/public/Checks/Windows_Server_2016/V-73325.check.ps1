<#
.SYNOPSIS
    This checks for compliancy on V-73325.

    Windows Server 2016 reversible password encryption must be disabled.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73325"

# Initial Variables
$Results = @{
    VulnID   = "V-73325"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$raw = $PreCheck.secEdit -match "ClearTextPassword"
[int]$value = $raw -split '= ' | select -Last 1
if ($value -eq 0) {
    $Results.Status = "NotAFinding"
    $Results.Details = "Reversible password encryption is disabled. See comments for details."
}
else {
    $Results.Status = "Open"
    $Results.Details = "Reversible password encryption is enabled. See comments for details."
}
$Results.Comments = "Secedit.exe reports: $raw"

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73325 [$($Results.Status)]"

#Return results
return $Results
