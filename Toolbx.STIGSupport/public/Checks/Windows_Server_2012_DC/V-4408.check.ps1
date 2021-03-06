<#
.SYNOPSIS
    This checks for compliancy on V-4408.

    Domain controllers must be configured to allow reset of machine account passwords.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-4408"

# Initial Variables
$Results = @{
    VulnID   = "V-4408"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
if ($PreCheck.hostType -eq "Domain Controller") {
    [string]$keyPath = "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\"
    [string]$valueName = "RefusePasswordChange"
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
            $Results.Details = "$valueName is set to $value, indicating machine account password reset is allowed. See comments for details."
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
else {
    $Results.Status = "Not_Applicable"
    $Results.Details = "Check is only valid for Domain Controllers."
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-4408 [$($Results.Status)]"

#Return results
return $Results
