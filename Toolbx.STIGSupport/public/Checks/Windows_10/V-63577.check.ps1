<#
.SYNOPSIS
    This checks for compliancy on V-63577.

    Hardened UNC Paths must be defined to require mutual authentication and integrity for at least the \\*\SYSVOL and \\*\NETLOGON shares.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-63577"

# Initial Variables
[string]$keyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\"
[string]$valueName = "NETLOGON"
[string]$pass = "RequireMutualAuthentication=1, RequireIntegrity=1"
[string]$vulnID = "V-63577"

#Perform necessary check
$Results = Compare-RegistryString -KeyPath $keyPath -ValueName $valueName -Expected $pass -ErrorAction SilentlyContinue;
if ($Results -eq $null -or $Results.Status -eq "") {
	$Results = @{
		VulnID   = $vulnID
		Status   = "Not_Reviewed"
	}
}
else {
	$Results.VulnID = $vulnID;
}

$valueName = "SYSVOL";
$NewResults = Compare-RegistryString -KeyPath $keyPath -ValueName $valueName -Expected $pass -ErrorAction SilentlyContinue;

if ($NewResults.Status -eq "Open" -or $Results.Status -eq "Open"){
	$Results.Status = "Open"
}
$Results.Details += "; " + $NewResults.Details;
$Results.Comments += "; " + $NewResults.Comments;

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-63577 [$($Results.Status)]"

#Return results
return $Results
