<#
.SYNOPSIS
    This checks for compliancy on V-26359.

    The Windows dialog box title for the legal banner must be configured.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-26359"

# Initial Variables
$Results = @{
    VulnID   = "V-26359"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
[string]$keyPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\"
[string]$valueName = "LegalNoticeCaption"
[string]$pass = "DoD Notice and Consent Banner"
[string]$pass2 = "US Department of Defense Warning Statement"
$key = (Get-ItemProperty $keyPath -Name $valueName -ErrorAction SilentlyContinue)
if (!$key) {
    $Results.Details = "Registry value at $keyPath with name $valueName was not found!"
    $Results.Status = "Open"
}
else {
    [string]$value = $key.$valueName
    if ($value -eq $pass -or $value -eq $pass2) {
        $Results.Status = "NotAFinding"
        $Results.Details = "$valueName is set to $value as appropriate. See comments for details."
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "$valueName is set to $value instead of '$pass' or '$pass2'! See comments for details."
    }
}
$Results.Comments = "Path: "+($key.PSPath -replace [regex]::escape("Microsoft.PowerShell.Core\Registry::"),"")
$Results.Comments = ($Results.Comments+"`r`nName: "+$valueName)
$Results.Comments = ($Results.Comments+"`r`nValue: "+($key.$valueName | foreach{ ("`r`n"+$_) }))


Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-26359 [$($Results.Status)]"

#Return results
return $Results
