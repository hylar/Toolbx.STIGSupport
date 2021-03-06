<#
.SYNOPSIS
    This checks for compliancy on V-46859.

    Security Warning for unsafe files must be set to prompt (Internet zone).

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-46859"

# Initial Variables
$Results = @{
    VulnID   = "V-46859"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
[string]$keyPath = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
[string]$valueName = "1806"
[int]$pass = 1
$key = (Get-ItemProperty $keyPath -Name $valueName -ErrorAction SilentlyContinue)
if (!$key) {
    $Results.Details = "Registry value at $keyPath with name $valueName was not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.$valueName
    if ($value -eq $pass) {
        $Results.Status = "NotAFinding"
        $Results.Details = "$valueName is set to $value, indicating unsafe files will display a security warning for the Internet Zone. See comments for details."
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "$valueName is set to $value, instead of $pass! See comments for details."
    }
}
$Results.Comments = "Path: $keyPath"
$Results.Comments = ($Results.Comments+"`r`nName: "+$valueName)
$Results.Comments = ($Results.Comments+"`r`nValue: "+($key.$valueName | ForEach-Object{ ("`r`n`t"+$_) }))

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-46859 [$($Results.Status)]"

#Return results
return $Results
