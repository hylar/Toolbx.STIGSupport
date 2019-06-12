<#
.SYNOPSIS
    This checks for compliancy on V-36773.

    The machine inactivity limit must be set to 15 minutes, locking the system with the screensaver.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-36773"

# Initial Variables
$Results = @{
    VulnID   = "V-36773"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
[string]$keyPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\"
[string]$valueName = "InactivityTimeoutSecs"
[int]$pass = 900
$key = (Get-ItemProperty $keyPath -Name $valueName)
if (!$key) {
    $Results.Details = "Registry value at $keyPath with name $valueName was not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.$valueName
    if ($value -le $pass -and $value -ne 0) {
        $Results.Status = "NotAFinding"
        $Results.Details = "$valueName is set to $value, indicating system locks after $value seconds of inactivity. See comments for details."
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "$valueName is set to $value instead of being less than $pass (but not 0)! See comments for details."
    }
}
$Results.Comments = "Path: "+($key.PSPath -replace [regex]::escape("Microsoft.PowerShell.Core\Registry::"),"")
$Results.Comments = ($Results.Comments+"`r`nName: "+$valueName)
$Results.Comments = ($Results.Comments+"`r`nValue: "+($key.$valueName | foreach{ ("`r`n"+$_) }))


Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-36773 [$($Results.Status)]"

#Return results
return $Results
