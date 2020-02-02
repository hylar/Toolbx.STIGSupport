<#
.SYNOPSIS
    This checks for compliancy on V-63627.

    Systems must at least attempt device authentication using certificates.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-63627"

# Initial Variables
[string]$keyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\"
[string]$valueName = "DevicePKInitEnabled"
[int]$pass = 1
$Results = @{
    VulnID   = "V-63627"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

if($PreCheck.hostType -ne "Non-Domain") {
	#Perform necessary check
	$key = (Get-ItemProperty $keyPath -Name $valueName -ErrorAction SilentlyContinue)
	if (!$key) {
		$Results.Details = "Registry value at $keyPath with name $valueName was not found."
		$Results.Status = "NotAFinding"
	}
	else {
		[int]$value = $key.$valueName
		if ($value -eq $pass) {
			$Results.Status = "NotAFinding"
			$Results.Details = "$valueName is set to $value. See comments for details."
		}
		else {
			$Results.Status = "Open"
			$Results.Details = "$valueName is set to $value, instead of $pass! See comments for details."
		}
	}
	$Results.Comments = $key | Select PSPath,PSChildName,$valueName | Out-String
	} else {

			$Results.Details = "System is standalone, this is NA"
			$Results.Status = "Not_Applicable"

	}
} else {

        $Results.Details = "System is standalone, this is NA"
        $Results.Status = "Not_Applicable"

}
Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-63627 [$($Results.Status)]"

#Return results
return $Results
