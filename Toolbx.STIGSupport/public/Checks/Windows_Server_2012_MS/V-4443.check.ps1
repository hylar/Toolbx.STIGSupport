<#
.SYNOPSIS
    This checks for compliancy on V-4443.

    Unauthorized remotely accessible registry paths and sub-paths must not be configured.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-4443"

# Initial Variables
$Results = @{
    VulnID   = "V-4443"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
[string]$keyPath = "HKLM:\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths\"
[string]$valueName = "Machine"
[array]$pass = "Software\Microsoft\OLAP Server","Software\Microsoft\Windows NT\CurrentVersion\Perflib","Software\Microsoft\Windows NT\CurrentVersion\Print","Software\Microsoft\Windows NT\CurrentVersion\Windows","System\CurrentControlSet\Control\ContentIndex","System\CurrentControlSet\Control\Print\Printers","System\CurrentControlSet\Control\Terminal Server","System\CurrentControlSet\Control\Terminal Server\UserConfig","System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration","System\CurrentControlSet\Services\Eventlog","System\CurrentControlSet\Services\Sysmonlog"
$key = (Get-ItemProperty $keyPath -Name $valueName -ErrorAction SilentlyContinue)
$fail = 0
$failNames = @()
if (!$key) {
    $Results.Details = "Registry value at $keyPath with name $valueName was not found!"
    $Results.Status = "Open"
}
else {
    $values = $key.$valueName
    foreach ($value in $values) {
        if ($pass -match [regex]::escape($value)) {
            #Good
        }
        else {
            $fail = 1
            $failNames += $value
        }
    }
    if ( $fail -eq 0 ) {
        $Results.Status = "NotAFinding"
        $Results.Details = "All remotely accessible registry paths match expected values. See comments for details."
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Remotely accessible registry paths don't match expected value! See comments for details."
        $Results.Comments = "-=Non-Compliant Values=-`r`n"
        $Results.Comments = ($Results.Comments+($failNames | Format-List | Out-String)+"`r`n")
    }
    $Results.Comments = ($Results.Comments+"-=All Values=-`r`n")
    $Results.Comments = ($Results.Comments+($values | Out-String)
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-4443 [$($Results.Status)]"

#Return results
return $Results
