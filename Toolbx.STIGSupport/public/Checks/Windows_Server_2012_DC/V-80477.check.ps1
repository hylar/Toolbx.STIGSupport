<#
.SYNOPSIS
    This checks for compliancy on V-80477.

    Windows PowerShell 2.0 must not be installed on Windows 2012/2012 R2.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-80477"

# Initial Variables
$Results = @{
    VulnID   = "V-80477"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$featureName = "PowerShell-v2"
$feature = Get-WindowsFeature | ? {$_.Name -eq $featureName}
if ($role.Installed -eq 0) {
    $Results.Status = "NotAFinding"
    $Results.Details = "The "+$feature.DisplayName+" feature is not installed. See comments for details."
}
if ($role.Installed -eq 1)  {
    $Results.Status = "Open"
    $Results.Details = "The "+$feature.DisplayName+" feature is installed! See comments for details."
}
$Results.Comments = $feature | Select-Object Name,DisplayName,Installed | Format-List | Out-String

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-80477 [$($Results.Status)]"

#Return results
return $Results
