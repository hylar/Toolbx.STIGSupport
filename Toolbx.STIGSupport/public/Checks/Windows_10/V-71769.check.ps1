<#
.SYNOPSIS
    This checks for compliancy on V-71769.

    Remote calls to the Security Account Manager (SAM) must be restricted to Administrators.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-71769"

# Initial Variables
[string]$keyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\"
[string]$valueName = "RestrictRemoteSAM"
[string]$pass = "O:BAG:BAD:(A;;RC;;;BA)"
[string]$vulnID = "V-71769"

#Perform necessary check
$Results = Compare-RegistryString -KeyPath $keyPath -ValueName $valueName -Expected $pass -ErrorAction SilentlyContinue;
if ($Results -eq $null -or $Results.Status -eq "") {
	$Results = @{
		VulnID   = $vulnID
		Status   = "Not_Reviewed"
	}
}
else {
	$Results.VulnID = $vulnID;
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-71769 [$($Results.Status)]"

#Return results
return $Results
