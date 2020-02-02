<#
.SYNOPSIS
    This checks for compliancy on V-63819.

    User Account Control must, at minimum, prompt administrators for consent on the secure desktop.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-63819"

# Initial Variables
[string]$keyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"
[string]$valueName = "ConsentPromptBehaviorAdmin"
[int]$pass = 2
[string]$vulnID = "V-63819"

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

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-63819 [$($Results.Status)]"

#Return results
return $Results
