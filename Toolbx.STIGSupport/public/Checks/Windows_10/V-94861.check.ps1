<#
.SYNOPSIS
    This checks for compliancy on V-94859.
	
	Windows 10 systems must use a BitLocker PIN with a minimum length of 6 digits for pre-boot authentication.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheckData)

Write-Verbose "Checking - V-94859"

# Initial Variables
[string]$keyPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE\"
[string]$valueName = "MinimumPIN"
[int]$pass = 6
[string]$vulnID = "V-94859"

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

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-63321 [$($Results.Status)]"

#Return results
return $Results