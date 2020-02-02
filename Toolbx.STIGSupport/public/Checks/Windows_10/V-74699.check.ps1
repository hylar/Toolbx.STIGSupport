<#
.SYNOPSIS
    This checks for compliancy on V-74699.

    Windows 10 must be configured to enable Remote host allows delegation of non-exportable credentials.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-74699"

# Initial Variables
[string]$keyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\"
[string]$valueName = "AllowProtectedCreds"
[int]$pass = 1
[string]$vulnID = "V-74699"

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

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-74699 [$($Results.Status)]"

#Return results
return $Results
