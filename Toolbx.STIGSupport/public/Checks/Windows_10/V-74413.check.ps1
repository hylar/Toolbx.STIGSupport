<#
.SYNOPSIS
    This checks for compliancy on V-74413.

    Windows 10 must be configured to prioritize ECC Curves with longer key lengths first.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-74413"

# Initial Variables
[string]$keyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002\"
[string]$valueName = "EccCurves"
[string[]]$pass = ("NistP384", "NistP256")
[string]$vulnID = "V-74413"

#Perform necessary check
$Results = Compare-RegistryMultiString -KeyPath $keyPath -ValueName $valueName -Expected $pass -ErrorAction SilentlyContinue;
if ($Results -eq $null -or $Results.Status -eq "") {
	$Results = @{
		VulnID   = $vulnID
		Status   = "Not_Reviewed"
	}
}
else {
	$Results.VulnID = $vulnID;
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-74413 [$($Results.Status)]"

#Return results
return $Results
