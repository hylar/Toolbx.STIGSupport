<#
.SYNOPSIS
    This checks for compliancy on V-63729.

    Passwords must not be saved in the Remote Desktop Client.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-63729"

# Initial Variables
[string]$keyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\"
[string]$valueName = "DisablePasswordSaving"
[int]$pass = 1
[string]$vulnID = "V-63729"

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

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-63729 [$($Results.Status)]"

#Return results
return $Results
