<#
.SYNOPSIS
    This checks for compliancy on V-46807.

    AutoComplete feature for forms must be disallowed.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param(`$PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-46807"

# Initial Variables
$Results = @{
    VulnID   = "V-46807"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
[string]$keyPath = "HKCU:\Software\Policies\Microsoft\Internet Explorer\Main"
[string]$valueName = "Use FormSuggest"
[string]$pass = 'no'
$key = (Get-ItemProperty $keyPath -Name $valueName)
if (!$key) {
    $Results.Details = "Registry value at $keyPath with name $valueName was not found!"
    $Results.Status = "Open"
}
else {
    [string]$value = $key.$valueName
    if ($value -eq $pass) {
        $Results.Status = "NotAFinding"
        $Results.Details = "$valueName is set to $value, indicating auto-complete is disabled. See comments for details."
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "$valueName is set to $value, instead of $pass! See comments for details."
    }
}
$Results.Comments = ($key | Select PSPath,PSChildName,$valueName | Out-String) -replace "`r`n`r`n",""

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-46807 [$($Results.Status)]"

#Return results
return $Results
