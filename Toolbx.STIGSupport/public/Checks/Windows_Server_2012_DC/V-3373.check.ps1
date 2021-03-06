<#
.SYNOPSIS
    This checks for compliancy on V-3373.

    The maximum age for machine account passwords must be set to requirements.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-3373"

# Initial Variables
$Results = @{
    VulnID   = "V-3373"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
[string]$keyPath = "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\"
[string]$valueName = "MaximumPasswordAge"
[int]$pass = 30
$key = (Get-ItemProperty $keyPath -Name $valueName -ErrorAction SilentlyContinue)
if (!$key) {
    $Results.Details = "Registry value at $keyPath with name $valueName was not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.$valueName
    if ($value -eq 0) {
        $Results.Status = "Open"
        $Results.Details = "$valueName is set to $value, instead of being between 1 and 30! See comments for details."
    }
    elseif ($value -le $pass) {
        $Results.Status = "NotAFinding"
        $Results.Details = "$valueName is set to $value. See comments for details, indicating the maximum age for the machine password is $value."
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "$valueName is set to $value, instead of being less than $pass! See comments for details."
    }
}
$Results.Comments = "Path: "+($key.PSPath -replace [regex]::escape("Microsoft.PowerShell.Core\Registry::"),"")
$Results.Comments = ($Results.Comments+"`r`nName: "+$valueName)
$Results.Comments = ($Results.Comments+"`r`nValue: "+($key.$valueName | foreach{ ("`r`n"+$_) }))

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-3373 [$($Results.Status)]"

#Return results
return $Results
