<#
.SYNOPSIS
    This checks for compliancy on V-94719.

    Windows 10 must be configured to prevent Windows apps from being activated by voice while the system is locked.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-94719"

# Initial Variables
[string]$keyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy\"
[string]$valueName = "LetAppsActivateWithVoice"
[int]$pass = 2
[string]$vulnID = "V-94719"
$Results = @{
    VulnID   = $vulnID
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty $keyPath -Name $valueName -ErrorAction SilentlyContinue)
if (!$key) {
    $next = $true
}
else {
    [int]$value = $key.$valueName
    if ($value -eq $pass) {
        $Results.Status = "Not_Applicable"
        $Results.Details = "$valueName is set to $value. See comments for details."
    }
    else {
        $next = $true
    }
}
if ($next){
	[string]$valueName = "LetAppsActivateWithVoiceAboveLock"
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
}
$Results.Comments = $key | Select PSPath,PSChildName,$valueName | Out-String

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-94719 [$($Results.Status)]"

#Return results
return $Results
