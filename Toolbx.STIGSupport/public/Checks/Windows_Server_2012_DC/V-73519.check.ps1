<#
.SYNOPSIS
    This checks for compliancy on V-73519.

    The Server Message Block (SMB) v1 protocol must be disabled on the SMB server.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73519"

# Initial Variables
$Results = @{
    VulnID   = "V-73519"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
[string]$keyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\"
[string]$valueName = "SMB1"
[int]$pass = 0
$key = (Get-ItemProperty $keyPath -Name $valueName -ErrorAction SilentlyContinue)
if (!$key) {
    $Results.Details = "Registry value at $keyPath with name $valueName was not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.$valueName
    if ($value -eq $pass) {
        $Results.Status = "NotAFinding"
        $Results.Details = "$valueName is set to $value, indicating Server Message Block v1 is disabled on the server. See comments for details."
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "$valueName is set to $value instead of $pass! See comments for details."
    }
}
$Results.Comments = "Path: "+($key.PSPath -replace [regex]::escape("Microsoft.PowerShell.Core\Registry::"),"")
$Results.Comments = ($Results.Comments+"`r`nName: "+$valueName)
$Results.Comments = ($Results.Comments+"`r`nValue: "+($key.$valueName | foreach{ ("`r`n"+$_) }))


Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73519 [$($Results.Status)]"

#Return results
return $Results
