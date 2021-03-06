<#
.SYNOPSIS
    This checks for compliancy on V-1120.

    File Transfer Protocol (FTP) servers must be configured to prevent anonymous logons.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-1120"

# Initial Variables
$Results = @{
    VulnID   = "V-1120"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$feature=(Get-WindowsFeature -Name Web-Ftp-Server).Installed
if ($feature -eq $false) {
    $Results.Status = "Not_Applicable"
    $Results.Details = "FTP Server feature is not installed on this server. See comments for details."
}
else {
    $Results.Status = "Open"
    $Results.Details = "FTP Server role is installed! CHECK IS WIP"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-1120 [$($Results.Status)]"

#Return results
return $Results
