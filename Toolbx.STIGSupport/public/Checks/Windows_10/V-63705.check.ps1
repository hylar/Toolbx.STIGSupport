<#
.SYNOPSIS
    This checks for compliancy on V-63705.

    InPrivate browsing in Microsoft Edge must be disabled.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-63705"

# Initial Variables
[string]$keyPath = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main\"
[string]$valueName = "AllowInPrivate"
[int]$pass = 0
[string]$vulnID = "V-63705"

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

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-63705 [$($Results.Status)]"

#Return results
return $Results
