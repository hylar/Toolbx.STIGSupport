<#
.SYNOPSIS
    This checks for compliancy on V-3289.

    Servers must have a host-based Intrusion Detection System.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-3289"

# Initial Variables
$Results = @{
    VulnID   = "V-3289"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$apps = (Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall) | foreach{Get-ItemProperty $_.PSPath} | ?{$_.DisplayName -eq "McAfee Endpoint Security Platform"}
$64apps = (Get-ChildItem HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall) | foreach{Get-ItemProperty $_.PSPath} | ?{$_.DisplayName -eq "McAfee Endpoint Security Platform"}
    if ($64apps) {
        $global:apps+=$64apps
    }
if ($apps) {
    [decimal]$version = ($apps.DisplayVersion | Select -First 1 | Out-String).Substring(0,3)
    if ($version -ge 10) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Found McAfee Endpoint Security Platform version $version. See comments for details."
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Found McAfee Endpoint Security Platform, but version is $version! See comments for details."
    }
}
else {
    $Results.Status = "Open"
    $Results.Details = "Cannot find installation of McAfee Endpoint Security Platform, please verify an intruder detection system exists!"
}
$Results.Comments =  ($apps | Select-Object  -First 1 DisplayName,DisplayVersion | Format-List | Out-String) -replace "`r`n`r`n","" -split "`r`n" | Select-Object -First 2

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-3289 [$($Results.Status)]"

#Return results
return $Results
