<#
.SYNOPSIS
    This checks for compliancy on V-71763.

    WDigest Authentication must be disabled.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-71763"

# Initial Variables
[string]$keyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest\"
[string]$valueName = "UseLogonCredential"
[int]$pass = 0
[string]$vulnID = "V-71763"

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

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-71763 [$($Results.Status)]"

#Return results
return $Results
