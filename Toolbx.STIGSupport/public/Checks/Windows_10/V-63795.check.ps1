<#
.SYNOPSIS
    This checks for compliancy on V-63795.

    Kerberos encryption types must be configured to prevent the use of DES and RC4 encryption suites.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-63795"

# Initial Variables
[string]$keyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\"
[string]$valueName = "SupportedEncryptionTypes"
[int]$pass = 2147483640
[string]$vulnID = "V-63795"

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

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-63795 [$($Results.Status)]"

#Return results
return $Results
