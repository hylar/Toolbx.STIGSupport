<#
.SYNOPSIS
    This checks for compliancy on V-63749.

    Anonymous enumeration of shares must be restricted.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-63749"

# Initial Variable
[string]$keyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\"
[string]$valueName = "RestrictAnonymous"
[int]$pass = 1
[string]$vulnID = "V-63749"

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

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-63749 [$($Results.Status)]"

#Return results
return $Results
