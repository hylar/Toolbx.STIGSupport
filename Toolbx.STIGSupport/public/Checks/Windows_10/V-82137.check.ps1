<#
.SYNOPSIS
    This checks for compliancy on V-82137.

    The use of personal accounts for OneDrive synchronization must be disabled.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-82137"

# Initial Variables
[string]$keyPath = "HKLM:\Software\Policies\Microsoft\OneDrive\"
[string]$valueName = "DisablePersonalSync"
[int]$pass = 1
[string]$vulnID = "V-82137"

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

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-82137 [$($Results.Status)]"

#Return results
return $Results
