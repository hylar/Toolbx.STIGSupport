<#
.SYNOPSIS
    This checks for compliancy on V-8322.

    Time synchronization must be enabled on the domain controller.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-8322"

# Initial Variables
$Results = @{
    VulnID   = "V-8322"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
[string]$keyPath = "HKLM:\System\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient\"
[string]$valueName = "Enabled"
[int]$pass = 1
$key = (Get-ItemProperty $keyPath -Name $valueName -ErrorAction SilentlyContinue)
[string]$keyPath2 = "HKLM:\System\CurrentControlSet\Services\W32Time\Parameters\"
[string]$valueName2 = "Type"
[array]$pass2 = "NT5DS", "NTP", "Allsync"
$key2 = (Get-ItemProperty $keyPath2 -Name $valueName2 -ErrorAction SilentlyContinue)

if (!$key -or !$key2) {
    $Results.Status = "Open"
    $Results.Details = "One or more of the registry values were not found; Please review!"
}
else {
    [int]$value = $key.$valueName
    [string]$value2 = $key2.$valueName2
    if ($value -eq $pass) {
        $Results.Status = "NotAFinding"
        $Results.Details = "$valueName is set to $value. See comments for details."
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "$valueName is set to $value, instead of $pass! See comments for details."
    }
    if ($pass2 -match $value2) {
        $Results.Details = "$valueName is set to $value. See comments for details."
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "$valueName is set to $value, instead of an acceptable value! See comments for details."
    }
}
$Results.Comments = "Path: " + ($key.PSPath -replace [regex]::escape("Microsoft.PowerShell.Core\Registry::"),"")
$Results.Comments = ($Results.Comments + "`r`nName: " + $valueName)
$Results.Comments = ($Results.Comments + "`r`nValue: " + ($key.$valueName | foreach{ ("`r`n`t" + $_) }))
$Results.Comments = ($Results.Comments + "`r`n`r`nPath: " + ($key2.PSPath -replace [regex]::escape("Microsoft.PowerShell.Core\Registry::"),""))
$Results.Comments = ($Results.Comments + "`r`nName: " + $valueName2)
$Results.Comments = ($Results.Comments + "`r`nValue: " + ($key2.$valueName2 | foreach{ ("`r`n`t" + $_) }))

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-8322 [$($Results.Status)]"

#Return results
return $Results
