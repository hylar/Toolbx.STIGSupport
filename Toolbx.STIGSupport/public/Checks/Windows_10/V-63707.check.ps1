<#
.SYNOPSIS
    This checks for compliancy on V-63707.

    The Windows SMB client must be enabled to perform SMB packet signing when possible.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-63707"

# Initial Variables
[string]$keyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\"
[string]$valueName = "EnableSecuritySignature"
[int]$pass = 1
[string]$vulnID = "V-63707"

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

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-63707 [$($Results.Status)]"

#Return results
return $Results
