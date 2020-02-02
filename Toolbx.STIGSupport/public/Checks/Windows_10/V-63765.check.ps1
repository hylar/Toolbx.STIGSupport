<#
.SYNOPSIS
    This checks for compliancy on V-63765.

    NTLM must be prevented from falling back to a Null session.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-63765"

# Initial Variables
[string]$keyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0\"
[string]$valueName = "allownullsessionfallback"
[int]$pass = 0
[string]$vulnID = "V-63765"

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

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-63765 [$($Results.Status)]"

#Return results
return $Results
