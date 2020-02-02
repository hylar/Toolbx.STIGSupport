<#
.SYNOPSIS
    This checks for compliancy on V-63709.

    The password manager function in the Edge browser must be disabled.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-63709"

# Initial Variables
[string]$keyPath = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main\"
[string]$valueName = "FormSuggest Passwords"
[string]$pass = "no"
[string]$vulnID = "V-63709"

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

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-63709 [$($Results.Status)]"

#Return results
return $Results
