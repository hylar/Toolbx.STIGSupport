<#
.SYNOPSIS
    This checks for compliancy on V-21956.

    IPv6 TCP data retransmissions must be configured to prevent resources from becoming exhausted.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-21956"

# Initial Variables
$Results = @{
    VulnID   = "V-21956"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
[string]$keyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\"
[string]$valueName = "TcpMaxDataRetransmissions"
[string]$pass = 3
$key = (Get-ItemProperty $keyPath -Name $valueName -ErrorAction SilentlyContinue)
if (!$key) {
    $Results.Details = "Registry value at $keyPath with name $valueName was not found!"
    $Results.Status = "Open"
}
else {
    [string]$value = $key.$valueName
    if ($value -le $pass) {
        $Results.Status = "NotAFinding"
        $Results.Details = "$valueName is set to $value, indicating that IPv6 data retransmissions are limited. See comments for details."
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "$valueName is set to $value instead being $pass or less! See comments for details."
    }
}
$Results.Comments = "Path: "+($key.PSPath -replace [regex]::escape("Microsoft.PowerShell.Core\Registry::"),"")
$Results.Comments = ($Results.Comments+"`r`nName: "+$valueName)
$Results.Comments = ($Results.Comments+"`r`nValue: "+($key.$valueName | foreach{ ("`r`n"+$_) }))


Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-21956 [$($Results.Status)]"

#Return results
return $Results
