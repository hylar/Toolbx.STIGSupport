<#
.SYNOPSIS
    This checks for compliancy on V-68849.

    Structured Exception Handling Overwrite Protection (SEHOP) must be enabled.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-68849"

# Initial Variables

if ($PreCheck.releaseId -le "1709") {
	[string]$keyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel\"
	[string]$valueName = "DisableExceptionChainValidation"
	[int]$pass = 0
	[string]$vulnID = "V-68849"

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
}
else {
	$Results = @{
		VulnID   = "V-68849"
		RuleID   = ""
		Details  = ""
		Comments = ""
		Status   = "Not_Applicable"
	}
}
Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-68849 [$($Results.Status)]"

#Return results
return $Results
