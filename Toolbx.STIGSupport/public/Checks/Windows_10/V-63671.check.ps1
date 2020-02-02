<#
.SYNOPSIS
    This checks for compliancy on V-63671.

    The default autorun behavior must be configured to prevent autorun commands.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-63671"

# Initial Variables
[string]$keyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\"
[string]$valueName = "NoAutorun"
[int]$pass = 1
[string]$vulnID = "V-63671"

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

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-63671 [$($Results.Status)]"

#Return results
return $Results
