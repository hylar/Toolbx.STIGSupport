<#
.SYNOPSIS
    This checks for compliancy on V-82145.

    If Enhanced diagnostic data is enabled it must be limited to the minimum required to support Windows Analytics.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-82145"

# Initial Variables
[string]$keyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection\"
[string]$valueName = "LimitEnhancedDiagnosticDataWindowsAnalytics"
[int]$pass = 1
[string]$vulnID = "V-82145"

if ([int]$PreCheck.releaseId -ge 1709) {

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
		VulnID   = "V-63319"
		RuleID   = ""
		Details  = ""
		Comments = "This setting requires v1709 or later of Windows 10; it is NA for prior versions."
		Status   = "Not_Applicable"
	}
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-82145 [$($Results.Status)]"

#Return results
return $Results
