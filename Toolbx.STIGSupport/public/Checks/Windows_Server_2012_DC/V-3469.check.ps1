<#
.SYNOPSIS
    This checks for compliancy on V-3469.

    Group Policies must be refreshed in the background if the user is logged on.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-3469"

# Initial Variables
$Results = @{
    VulnID   = "V-3469"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
[string]$keyPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\system\"
[string]$valueName = "DisableBkGndGroupPolicy"
[int]$pass = 0
$key = (Get-ItemProperty $keyPath -Name $valueName -ErrorAction SilentlyContinue)
if (!$key) {
    $Results.Status = "NotAFinding"
    $Results.Details = "Registry value at $keyPath with name $valueName does not exist indicating this is not a finding."
}
else {
    [int]$value = $key.$valueName
    if ($value -eq $pass) {
        $Results.Status = "NotAFinding"
        $Results.Details = "$valueName is set to $value, indicating that Group Policies are allowed to refresh in background. See comments for details."
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "$valueName is set to $value, instead of $pass! See comments for details."
    }
}
$Results.Comments = "Path: "+($key.PSPath -replace [regex]::escape("Microsoft.PowerShell.Core\Registry::"),"")
$Results.Comments = ($Results.Comments+"`r`nName: "+$valueName)
$Results.Comments = ($Results.Comments+"`r`nValue: "+($key.$valueName | foreach{ ("`r`n"+$_) }))

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-3469 [$($Results.Status)]"

#Return results
return $Results
