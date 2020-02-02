<#
.SYNOPSIS
    This checks for compliancy on V-74415.

    Windows 10 must be configured to prevent Microsoft Edge browser data from being cleared on exit.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-74415"

# Initial Variables
[string]$keyPath = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Privacy\"
[string]$valueName = "ClearBrowsingHistoryOnExit"
[int]$pass = 0
[string]$vulnID = "V-74415"

#Perform necessary check
$Results = Compare-RegistryDWord -KeyPath $keyPath -ValueName $valueName -Expected $pass -ErrorAction SilentlyContinue;
if ($Results -eq $null -or $Results.Status -eq "") {
	$Results = @{
		VulnID   = $vulnID
		Status   = "Not_Reviewed"
	}
}
else {
	$Results.VulnID = $vulnID;
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-74415 [$($Results.Status)]"

#Return results
return $Results
