<#
.SYNOPSIS
    This checks for compliancy on V-36707.

    Windows SmartScreen must be enabled on Windows 2012/2012 R2.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-36707"

# Initial Variables
$Results = @{
    VulnID   = "V-36707"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
[string]$keyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\"
[string]$valueName = "EnableSmartScreen"
[int]$pass = 1
[int]$pass2 = 2
$key = (Get-ItemProperty $keyPath -Name $valueName -ErrorAction SilentlyContinue)
if (!$key) {
    $Results.Details = "Registry value at $keyPath with name $valueName was not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.$valueName
    if ($value -eq $pass -or $value -eq $pass2) {
        $Results.Status = "NotAFinding"
        $Results.Details = "$valueName is set to $value, indicating SmartScreen prompts for unknown software. See comments for details."
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "$valueName is set to $value instead of $pass! See comments for details."
    }
}

$Results.Comments = "Path: "+($key.PSPath -replace [regex]::escape("Microsoft.PowerShell.Core\Registry::"),"")
$Results.Comments = ($Results.Comments+"`r`nName: "+$valueName)
$Results.Comments = ($Results.Comments+"`r`nValue: "+($key.$valueName | foreach{ ("`r`n"+$_) }))

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-36707 [$($Results.Status)]"

#Return results
return $Results
