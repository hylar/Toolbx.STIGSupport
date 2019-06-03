<#
.SYNOPSIS
    This checks for compliancy on V-64717.

    Prevent ignoring certificate errors option must be enabled.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-64717"

# Initial Variables
$Results = @{
    VulnID   = "V-64717"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
[string]$keyPath = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"
[string]$valueName = "PreventIgnoreCertErrors"
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
        $Results.Details = "$valueName is set to $value, indicating that certificate error warnings cannot be ignored. See comments for details."
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "$valueName is set to $value, instead of $pass! See comments for details."
    }
}
$Results.Comments = (($key | Select-Object PSPath,PSChildName,$valueName) | Format-List | Out-String) -replace [regex]::escape("Microsoft.PowerShell.Core\Registry::"),""

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-64717 [$($Results.Status)]"

#Return results
return $Results
