<#
.SYNOPSIS
    This checks for compliancy on V-46815.

    Turn on the auto-complete feature for user names and passwords on forms must be disabled.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-46815"

# Initial Variables
$Results = @{
    VulnID   = "V-46815"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
[string]$keyPath = "HKCU:\Software\Policies\Microsoft\Internet Explorer\Main"
[string]$valueName = "FormSuggest Passwords"
[string]$pass = 'no'
[string]$keyPath2 = "HKCU:\Software\Policies\Microsoft\Internet Explorer\Main"
[string]$valueName2 = "FormSuggest PW Ask"
[string]$pass2 = 'no'
$key = (Get-ItemProperty $keyPath -Name $valueName -ErrorAction SilentlyContinue)
$key2 = (Get-ItemProperty $keyPath2 -Name $valueName2 -ErrorAction SilentlyContinue)
if (!$key) {
    $Results.Details = "Registry value at $keyPath with name $valueName was not found!"
    $Results.Status = "Open"
}
else {
    [string]$value = $key.$valueName
    [string]$value2 = $key2.$valueName2
    if ($value -eq $pass -and $value2 -eq $pass2) {
        $Results.Status = "NotAFinding"
        $Results.Details = "$valueName is set to $value and $valueName2 is set to $value2, indicating auto-completion for user names and passwords on forums is disabled. See comments for details."
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "One of the tested values was set incorrectly! See comments for details."
        $Results.Details += "`r`n$valueName is set to $value, it should be: $pass"
        $Results.Details += "`r`n$valueName2 is set to $value2, it should be: $pass2"
    }
}

$Results.Comments = "Path: $keyPath"
$Results.Comments = ($Results.Comments+"`r`nName: "+$valueName)
$Results.Comments = ($Results.Comments+"`r`nValue: "+($key.$valueName | ForEach-Object{ ("`r`n`t"+$_) }))
$Results.Comments += "`r`n"+((($key2 | Select-Object PSPath,PSChildName,$valueName2) | Format-List | Out-String) -replace [regex]::escape("Microsoft.PowerShell.Core\Registry::"),"" -replace "`r`n`r`n","")

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-46815 [$($Results.Status)]"

#Return results
return $Results
