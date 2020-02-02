<#
.SYNOPSIS
    This checks for compliancy on V-63763.

    Services using Local System that use Negotiate when reverting to NTLM authentication must use the computer identity vs. authenticating anonymously.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-63763"

# Initial Variables
[string]$keyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\LSA\"
[string]$valueName = "UseMachineId"
[int]$pass = 1
[string]$vulnID = "V-63763"

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

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-63763 [$($Results.Status)]"

#Return results
return $Results
