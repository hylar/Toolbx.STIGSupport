<#
.SYNOPSIS
    This checks for compliancy on V-63647.

    Outgoing secure channel traffic must be signed when possible.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-63647"

# Initial Variables
[string]$keyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\"
[string]$valueName = "SignSecureChannel"
[int]$pass = 1
[string]$vulnID = "V-63647"

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

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-63647 [$($Results.Status)]"

#Return results
return $Results
