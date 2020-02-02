<#
.SYNOPSIS
    This checks for compliancy on V-63821.

    User Account Control must automatically deny elevation requests for standard users.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-63821"

# Initial Variables
[string]$keyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"
[string]$valueName = "ConsentPromptBehaviorUser"
[int]$pass = 0
[string]$vulnID = "V-63821"

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

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-63821 [$($Results.Status)]"

#Return results
return $Results
