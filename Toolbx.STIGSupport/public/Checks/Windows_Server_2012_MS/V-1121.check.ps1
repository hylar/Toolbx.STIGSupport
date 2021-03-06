<#
.SYNOPSIS
    This checks for compliancy on V-1121.

    File Transfer Protocol (FTP) servers must be configured to prevent access to the system drive.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-1121"

# Initial Variables
$Results = @{
    VulnID   = "V-1121"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
#CHECK IS WIP
$featureName = "Web-Ftp-Server"
$feature=Get-WindowsFeature -Name $featureName
if ($feature.Installed -eq $false) {
    $Results.Status = "Not_Applicable"
    $Results.Details = "FTP Server feature is not installed on this server. See comments for details."
}
else {
    $Results.Status = "Open"
    $Results.Details = "FTP Server role is installed, please investigate! See comments for details."
}
$Results.Comments = $feature | Select-Object FeatureName,DisplayName,State | Format-List | Out-String

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-1121 [$($Results.Status)]"

#Return results
return $Results
