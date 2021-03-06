<#
.SYNOPSIS
    This checks for compliancy on V-1157.

    The Smart Card removal option must be configured to Force Logoff or Lock Workstation.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-1157"

# Initial Variables
$Results = @{
    VulnID   = "V-1157"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
[string]$keyPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\"
[string]$valueName = "SCRemoveOption"
[int]$pass = 1
[int]$pass2 = 2
$key = (Get-ItemProperty $keyPath -Name $valueName -ErrorAction SilentlyContinue)
if (!$key) {
    $Results.Details = "Registry value at $keyPath with name $valueName was not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.$valueName
    if ($value -eq $pass) {
        $Results.Status = "NotAFinding"
        $Results.Details = "$valueName is set to $value, indicating the workstation locks on smartcard removal. See comments for details."
    }
    elseif ($value -eq $pass2) {
        $Results.Status = "NotAFinding"
        $Results.Details = "$valueName is set to $value, indicating the user if logged off on smartcard removal. See comments for details."
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "$valueName is set to $value, instead of $pass or $pass2! See comments for details."
    }
}
$Results.Comments = "Path: "+($key.PSPath -replace [regex]::escape("Microsoft.PowerShell.Core\Registry::"),"")
$Results.Comments = ($Results.Comments+"`r`nName: "+$valueName)
$Results.Comments = ($Results.Comments+"`r`nValue: "+($key.$valueName | foreach{ ("`r`n"+$_) }))

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-1157 [$($Results.Status)]"

#Return results
return $Results
