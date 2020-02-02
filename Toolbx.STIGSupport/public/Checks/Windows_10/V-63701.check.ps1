<#
.SYNOPSIS
    This checks for compliancy on V-63701.

    Users must not be allowed to ignore Windows Defender SmartScreen filter warnings for unverified files in Microsoft Edge.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-63701"

# Initial Variables
[string]$keyPath = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter\"
[string]$valueName = "PreventOverrideAppRepUnknown"
[int]$pass = 1
[string]$vulnID = "V-63701"

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

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-63701 [$($Results.Status)]"

#Return results
return $Results
