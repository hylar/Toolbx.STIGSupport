<#
.SYNOPSIS
    This checks for compliancy on V-4442.

    The system must be configured to have password protection take effect within a limited time frame when the screen saver becomes active.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-4442"

# Initial Variables
$Results = @{
    VulnID   = "V-4442"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
[string]$keyPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\"
[string]$valueName = "ScreenSaverGracePeriod"
[int]$pass = 5
$key = (Get-ItemProperty $keyPath -Name $valueName -ErrorAction SilentlyContinue)
if (!$key) {
    $Results.Details = "Registry value at $keyPath with name $valueName was not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.$valueName
    if ($value -le $pass) {
        $Results.Status = "NotAFinding"
        $Results.Details = "$valueName is set to $value, indicating password protection takes effect $value seconds after screen saver. See comments for details."
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "$valueName is set to $value, instead of being $pass or less! See comments for details."
    }
}
$Results.Comments = "Path: "+($key.PSPath -replace [regex]::escape("Microsoft.PowerShell.Core\Registry::"),"")
$Results.Comments = ($Results.Comments+"`r`nName: "+$valueName)
$Results.Comments = ($Results.Comments+"`r`nValue: "+($key.$valueName | foreach{ ("`r`n"+$_) }))

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-4442 [$($Results.Status)]"

#Return results
return $Results
