<#
.SYNOPSIS
    This checks for compliancy on V-3338.

    Named pipes that can be accessed anonymously must be configured with limited values on domain controllers.
    Named pipes that can be accessed anonymously must be configured to contain no values on member servers.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-3338"

# Initial Variables
$Results = @{
    VulnID   = "V-3338"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
if ($PreCheck.hostType -eq "Domain Controller") {
    #Domain Controller check
    [string]$keyPath = "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters\"
    [string]$valueName = "NullSessionPipes"
    [array]$pass = "netlogon","samr","lsarpc"
    $key = (Get-ItemProperty $keyPath -Name $valueName -ErrorAction SilentlyContinue)
    if (!$key) {
        $Results.Details = "Registry value at $keyPath with name $valueName was not found!"
        $Results.Status = "Open"
    }
    else {
        [array]$value = $key.$valueName
        [int]$fail = 0
        foreach ($v in $value) {
            if ($pass -match $v) {}
            else {[int]$fail = 1}
        }
        if ($value -eq "") {
            [int]$fail = 1
        }
        if ([int]$fail -eq 0) {
            $Results.Status = "NotAFinding"
            $Results.Details = "$valueName is contains netlogon, samr, and lsarpc. This indicates only these pipes can be accessed anonymously. See comments for details."
        }
        else {
            $Results.Status = "Open"
            $Results.Details = "$valueName is not set to expected values; Please review! See comments for details."
        }
    }
}
else {
    #Member Server check
    [string]$keyPath = "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters\"
    [string]$valueName = "NullSessionPipes"
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
            $Results.Details = "$valueName is set to (blank), indicating no pipes can be accessed anonymously. See comments for details."
        }
        else {
            $Results.Status = "Open"
            $Results.Details = "$valueName is set to $value, instead of <blank>! See comments for details."
        }
    }
}
$Results.Comments = "Path: "+($key.PSPath -replace [regex]::escape("Microsoft.PowerShell.Core\Registry::"),"")
$Results.Comments = ($Results.Comments+"`r`nName: "+$valueName)
$Results.Comments = ($Results.Comments+"`r`nValue: "+($key.$valueName | foreach{ ("`r`n"+$_) }))

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-3338 [$($Results.Status)]"

#Return results
return $Results
