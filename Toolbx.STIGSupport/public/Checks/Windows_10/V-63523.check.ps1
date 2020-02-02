<#
.SYNOPSIS
    This checks for compliancy on V-63523.

    The Security event log size must be configured to 1024000 KB or greater.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-63523"

# Initial Variables
[string]$keyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\"
[string]$valueName = "MaxSize"
[int]$pass = 1024000
[string]$vulnID = "V-63523"

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

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-63523 [$($Results.Status)]"

#Return results
return $Results
