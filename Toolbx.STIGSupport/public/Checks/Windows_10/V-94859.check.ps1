<#
.SYNOPSIS
    This checks for compliancy on V-94859
	
	Windows 10 systems must use a BitLocker PIN for pre-boot authentication.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-94859"

# Initial Variables
[string]$keyPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE\"
[string]$valueName = "UseAdvancedStartup"
[int]$pass = 1
[string]$vulnID = "V-94859"

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

if ($Results.Status -ne "Open") {
	$valueName1 = "UseTPMPIN";
	$NewResults1 = Compare-RegistryDWord -KeyPath $keyPath -ValueName $valueName1 -Expected $pass -ErrorAction SilentlyContinue;

	$valueName2 = "UseTPMKeyPIN";
	$NewResults2 = Compare-RegistryDWord -KeyPath $keyPath -ValueName $valueName2 -Expected $pass -ErrorAction SilentlyContinue;

	if ($NewResults1.Status -eq "Open" -and $NewResults2.Status -eq "Open"){
		$Results.Status = "Open"
	}
	$Results.Details += "; " + $NewResults1.Details + "; " + $NewResults2.Details;
	$Results.Comments += "; " + $NewResults1.Comments + "; " + $NewResults2.Comments;
}
Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-94859 [$($Results.Status)]"

#Return results
return $Results