<#
.SYNOPSIS
    This checks for compliancy on V-1090.

    Caching of logon credentials must be limited.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-1090"

# Initial Variables
$Results = @{
    VulnID   = "V-1090"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
if($PreCheck.HostType -ne "Non-Domain"){
    [string]$keyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\"
    [string]$valueName = "CachedLogonsCount"
    [int]$pass = 4
    $key = (Get-ItemProperty $keyPath -Name $valueName -ErrorAction SilentlyContinue)
    if (!$key) {
        $Results.Details = "Registry value at $keyPath with name $valueName was not found!"
        $Results.Status = "Open"
    }
    else {
        [int]$value = $key.$valueName
        if ($value -le $pass) {
            $Results.Status = "NotAFinding"
            $Results.Details = "$valueName is set to $value, indicating only $value logon credentials are cached. See comments for details."
        }
        else {
            $Results.Status = "Open"
            $Results.Details = "$valueName is set to $value, instead of $pass! See comments for details."
        }
    }
    $Results.Comments = "Path: "+($key.PSPath -replace [regex]::escape("Microsoft.PowerShell.Core\Registry::"),"")
$Results.Comments = ($Results.Comments+"`r`nName: "+$valueName)
$Results.Comments = ($Results.Comments+"`r`nValue: "+($key.$valueName | foreach{ ("`r`n"+$_) }))
}
else{
    $Results.Details = "Check is only applicable to domain-joined machines."
    $Results.Status = "Not_Applicable"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-1090 [$($Results.Status)]"

#Return results
return $Results
