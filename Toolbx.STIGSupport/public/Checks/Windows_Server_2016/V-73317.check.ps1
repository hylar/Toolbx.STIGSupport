<#
.SYNOPSIS
    This checks for compliancy on V-73317.

    Windows Server 2016 maximum password age must be configured to 60 days or less.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73317"

# Initial Variables
$Results = @{
    VulnID   = "V-73317"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$raw = $PreCheck.secEdit -match "^MaximumPasswordAge" | Select -First 1
[int]$value = $raw -split '= ' | select -Last 1
if ($value -le 60 -and $value -ne 0) {
    $Results.Status = "NotAFinding"
    $Results.Details = "Maximum password age is set correctly. Secedit.exe reports: $raw"
}
else {
    $Results.Status = "Open"
    $Results.Details = "Maximum password age is NOT set correctly. Secedit.exe reports: $raw"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73317 [$($Results.Status)]"

#Return results
return $Results
