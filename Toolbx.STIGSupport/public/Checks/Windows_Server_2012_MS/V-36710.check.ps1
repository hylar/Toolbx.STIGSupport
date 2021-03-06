<#
.SYNOPSIS
    This checks for compliancy on V-36710.

    Automatic download of updates from the Windows Store must be turned off.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-36710"

# Initial Variables
$Results = @{
    VulnID   = "V-36710"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
if (!(Get-Item "$Env:SystemRoot\WinStore\") -and !(Get-Item "C:\Windows\WinStore\")) {
    $Results.Status = "Not_Applicable"
    $Results.Details = "The Windows Store path does not exist, indicating that it is not installed. This check is NA."
}
else {
    [string]$keyPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore\"
    [string]$altPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore\WindowsUpdate\"
    [string]$valueName = "AutoDownload"
    [int]$pass = 2
    $key = (Get-ItemProperty $keyPath -Name $valueName -ErrorAction SilentlyContinue)
    if (!$key) {
        $key = (Get-ItemProperty $altPath -Name $valueName)
    }
    if (!$key) {
        $Results.Details = "Registry value at $keyPath with name $valueName was not found!"
        $Results.Details = ($Results.Details+"`r`nRegistry value at $altPath with name $valueName was not found!")
        $Results.Status = "Open"
    }
    else {
        [int]$value = $key.$valueName
        if ($value -eq $pass) {
            $Results.Status = "NotAFinding"
            $Results.Details = "$valueName is set to $value, indicating automatic download of Windows Store updates is disallowed. See comments for details."
        }
        else {
            $Results.Status = "Open"
            $Results.Details = "$valueName is set to $value instead of $pass! See comments for details."
        }
    }
    $Results.Comments = "Path: "+($key.PSPath -replace [regex]::escape("Microsoft.PowerShell.Core\Registry::"),"")
    $Results.Comments = ($Results.Comments+"`r`nName: "+$valueName)
    $Results.Comments = ($Results.Comments+"`r`nValue: "+($key.$valueName | foreach{ ("`r`n"+$_) }))
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-36710 [$($Results.Status)]"

#Return results
return $Results
