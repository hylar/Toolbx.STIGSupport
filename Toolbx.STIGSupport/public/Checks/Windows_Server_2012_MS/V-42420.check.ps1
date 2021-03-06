<#
.SYNOPSIS
    This checks for compliancy on V-42420.

    A host-based firewall must be installed and enabled on the system.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-42420"

# Initial Variables
$Results = @{
    VulnID   = "V-42420"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$apps=(Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall) | foreach{Get-ItemProperty $_.PSPath} | ?{$_.DisplayName -like "McAfee Endpoint Security Firewall"}
$64apps=(Get-ChildItem HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall) | foreach{Get-ItemProperty $_.PSPath} | ?{$_.DisplayName -eq "McAfee Endpoint Security Firewall"}
    if ($64apps) {
        $global:apps+=$64apps
    }
if (!$apps) {
    $Results.Status = "Open"
    $Results.Details = "Cannot find installation of McAfee Endpoint Security Firewall, please verify a host-based firewall is in placed!"
}
else {
    [string]$version = ($apps.DisplayVersion | Select -First 1 | Out-String) -replace "`r`n",""
    $Results.Status = "NotAFinding"
    $Results.Details = "Found McAfee Endpoint Security Firewall version $version. See comments for details."
}
$Results.Comments =  ($apps | Select-Object  -First 1 DisplayName,DisplayVersion | Format-List | Out-String) -replace "`r`n`r`n","" -split "`r`n" | Select-Object -First 2

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-42420 [$($Results.Status)]"

#Return results
return $Results
