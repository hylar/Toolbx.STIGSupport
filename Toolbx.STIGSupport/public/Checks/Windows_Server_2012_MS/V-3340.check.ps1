<#
.SYNOPSIS
    This checks for compliancy on V-3340.

    Network shares that can be accessed anonymously must not be allowed.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-3340"

# Initial Variables
$Results = @{
    VulnID   = "V-3340"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
[string]$keyPath = "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters\"
[string]$valueName = "NullSessionShares"
[string]$pass = ""
$key = (Get-ItemProperty $keyPath -Name $valueName -ErrorAction SilentlyContinue)
if (!$key) {
    $Results.Details = "Registry value at $keyPath with name $valueName was not found!"
    $Results.Status = "Open"
}
else {
    [string]$value = $key.$valueName
    if ($value -eq $pass) {
        $Results.Status = "NotAFinding"
        $Results.Details = "$valueName is set to (blank), indicating no shares may be accessd anonymously. See comments for details."
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "$valueName is set to $value, instead of (blank)! See comments for details."
    }
}
$Results.Comments = "Path: "+($key.PSPath -replace [regex]::escape("Microsoft.PowerShell.Core\Registry::"),"")
$Results.Comments = ($Results.Comments+"`r`nName: "+$valueName)
$Results.Comments = ($Results.Comments+"`r`nValue: "+($key.$valueName | foreach{ ("`r`n"+$_) }))

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-3340 [$($Results.Status)]"

#Return results
return $Results
