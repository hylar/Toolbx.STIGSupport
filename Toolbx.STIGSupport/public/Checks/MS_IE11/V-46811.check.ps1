<#
.SYNOPSIS
    This checks for compliancy on V-46811.

    Crash Detection management must be enforced.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-46811"

# Initial Variables
$Results = @{
    VulnID   = "V-46811"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
[string]$keyPath = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Restrictions"
[string]$valueName = "NoCrashDetection"
[int]$pass = 1
$key = (Get-ItemProperty $keyPath -Name $valueName)
if (!$key) {
    $Results.Details = "Registry value at $keyPath with name $valueName was not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.$valueName
    if ($value -eq $pass) {
        $Results.Status = "NotAFinding"
        $Results.Details = "$valueName is set to $value, indicating automatic crash detection reporting is disabled. See comments for details."
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "$valueName is set to $value, instead of $pass! See comments for details."
    }
}
$Results.Comments = (($key | Select-Object PSPath,PSChildName,$valueName) | Format-List | Out-String) -replace [regex]::escape("Microsoft.PowerShell.Core\Registry::"),""

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-46811 [$($Results.Status)]"

#Return results
return $Results
