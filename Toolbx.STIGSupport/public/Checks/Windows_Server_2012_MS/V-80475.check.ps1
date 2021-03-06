<#
.SYNOPSIS
    This checks for compliancy on V-80475.

    PowerShell script block logging must be enabled on Windows 2012/2012 R2.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-80475"

# Initial Variables
$Results = @{
    VulnID   = "V-80475"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
if ($PSVersionTable.PSVersion.Major -ge 5) {
    $Results.Status = "Not_Applicable"
    $Results.Details = "PowerShell is version 5 or greater, not applicable. See comments for details."
    $Results.Comments = $PSVersionTable | Format-List | Out-String
}
else {
    [string]$keyPath = "HKLM:\SOFTWARE\ Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\"
    [string]$valueName = "EnableScriptBlockLogging"
    [int]$pass = 1
    $key = (Get-ItemProperty $keyPath -Name $valueName -ErrorAction SilentlyContinue)
    if (!$key) {
        $Results.Details = "PowerShell is bellow version 5.0 and registry value at $keyPath with name $valueName was not found!"
        $Results.Status = "Open"
    }
    else {
        [int]$value = $key.$valueName
        if ($value -eq $pass) {
            $Results.Status = "NotAFinding"
            $Results.Details = "PowerShell is bellow version 5.0 and $valueName is set to $value, indicating that details of PowerShell commands and scripts are recorded. See comments for details."
        }
        else {
            $Results.Status = "Open"
            $Results.Details = "PowerShell is bellow version 5.0 and $valueName is set to $value instead of $pass! See comments for details."
        }
    }
    $Results.Comments = "Path: "+($key.PSPath -replace [regex]::escape("Microsoft.PowerShell.Core\Registry::"),"")
    $Results.Comments = ($Results.Comments+"`r`nName: "+$valueName)
    $Results.Comments = ($Results.Comments+"`r`nValue: "+($key.$valueName | foreach{ ("`r`n"+$_) }))
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-80475 [$($Results.Status)]"

#Return results
return $Results
