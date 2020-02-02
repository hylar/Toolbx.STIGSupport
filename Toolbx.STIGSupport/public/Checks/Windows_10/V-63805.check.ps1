<#
.SYNOPSIS
    This checks for compliancy on V-63805.

    The system must be configured to meet the minimum session security requirement for NTLM SSP based clients.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-63805"

# Initial Variables
[string]$keyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\"
[string]$valueName = "NTLMMinClientSec"
[int]$pass = 537395200
[string]$vulnID = "V-63805"

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

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-63805 [$($Results.Status)]"

#Return results
return $Results
