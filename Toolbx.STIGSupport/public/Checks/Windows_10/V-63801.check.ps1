<#
.SYNOPSIS
    This checks for compliancy on V-63801.

    The LanMan authentication level must be set to send NTLMv2 response only, and to refuse LM and NTLM.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-63801"

# Initial Variables
[string]$keyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\"
[string]$valueName = "LmCompatibilityLevel"
[int]$pass = 5
[string]$vulnID = "V-63801"

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

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-63801 [$($Results.Status)]"

#Return results
return $Results
