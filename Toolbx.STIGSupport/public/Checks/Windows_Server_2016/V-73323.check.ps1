<#
.SYNOPSIS
    This checks for compliancy on V-73323.

    Windows Server 2016 must have the built-in Windows password complexity policy enabled.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73323"

# Initial Variables
$Results = @{
    VulnID   = "V-73323"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$raw = $PreCheck.secEdit -match "PasswordComplexity"
[int]$value = $raw -split '= ' | select -Last 1
if ($value -eq 1) {
    $Results.Status = "NotAFinding"
    $Results.Details = "Password complexity is enabled. Secedit.exe reports: $raw"
}
else {
    $Results.Status = "Open"
    $Results.Details = "Password complexity is NOT enabled. Secedit.exe reports: $raw"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73323 [$($Results.Status)]"

#Return results
return $Results
