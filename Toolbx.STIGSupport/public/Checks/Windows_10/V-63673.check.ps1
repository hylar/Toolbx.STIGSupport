<#
.SYNOPSIS
    This checks for compliancy on V-63673.

    Autoplay must be disabled for all drives.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-63673"

# Initial Variables
[string]$keyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\"
[string]$valueName = "NoDriveTypeAutoRun"
[int]$pass = 255
[string]$vulnID = "V-63673"

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

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-63673 [$($Results.Status)]"

#Return results
return $Results
