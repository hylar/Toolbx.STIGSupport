<#
.SYNOPSIS
    This checks for compliancy on V-63563.

    The system must be configured to prevent Internet Control Message Protocol (ICMP) redirects from overriding Open Shortest Path First (OSPF) generated routes.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-63563"

# Initial Variables
[string]$keyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\"
[string]$valueName = "EnableICMPRedirect"
[int]$pass = 0
[string]$vulnID = "V-63563"

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

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-63563 [$($Results.Status)]"

#Return results
return $Results
