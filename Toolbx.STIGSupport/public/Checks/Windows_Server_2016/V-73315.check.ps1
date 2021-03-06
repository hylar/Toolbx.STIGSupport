<#
.SYNOPSIS
    This checks for compliancy on V-73315.

    Windows Server 2016 password history must be configured to 24 passwords remembered.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73315"

# Initial Variables
$Results = @{
    VulnID   = "V-73315"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$raw = $PreCheck.secEdit -match "PasswordHistorySize"
[int]$value = $raw -split '= ' | select -Last 1
if ($value -eq 24) {
    $Results.Status = "NotAFinding"
    $Results.Details = "Number of passwords remembered is set correctly. Secedit.exe reports: $raw"
}
else {
    $Results.Status = "Open"
    $Results.Details = "Number of passwords remembered is NOT set correctly. Secedit.exe reports: $raw"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73315 [$($Results.Status)]"

#Return results
return $Results
