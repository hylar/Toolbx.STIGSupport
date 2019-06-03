<#
.SYNOPSIS
    This checks for compliancy on V-46787.

    Internet Explorer Processes for restricting pop-up windows must be enforced (Reserved).

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-46787"

# Initial Variables
$Results = @{
    VulnID   = "V-46787"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
[string]$keyPath = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS"
[string]$valueName = "(Reserved)"
[int]$pass = 1
$key = (Get-ItemProperty $keyPath -Name $valueName)
if (!$key) {
    $Results.Details = "Registry value at $keyPath with name $valueName was not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.$valueName
    if ($value -eq $pass) {
        $Results.Status = "NotAFinding"
        $Results.Details = "$valueName is set to $value, indicating pop-up window restrictions are in effect. See comments for details."
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "$valueName is set to $value, instead of $pass! See comments for details."
    }
}
$Results.Comments = ($key | Select PSPath,PSChildName,$valueName | Out-String) -replace "`r`n`r`n",""

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-46787 [$($Results.Status)]"

#Return results
return $Results
