<#
.SYNOPSIS
    This checks for compliancy on V-46473.

    Turn off Encryption Support must be enabled.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)] Checking - V-46473"

# Initial Variables
$Results = @{
    VulnID   = "V-46473"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
[string]$keyPath = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"
[string]$valueName = "SecureProtocols"
[int]$pass = 2560

$key = (Get-ItemProperty $keyPath -Name $valueName -ErrorAction SilentlyContinue)

if (!$key) {

    $Results.Details = "Registry value at $keyPath with name $valueName was not found!"
    $Results.Status = "Open"

}
else {

    [int]$value = $key.$valueName

    if ($value -eq $pass) {

        $Results.Status = "NotAFinding"
        $Results.Details = "$valueName is set to $value, indicating that only TLS 1.1 and 1.2 are enabled. See comments for details."

    }
    else {

        $Results.Status = "Open"
        $Results.Details = "$valueName is set to $value, instead of $pass! See comments for details."

    }
}

$Results.Comments = "Path: $keyPath"
$Results.Comments = ($Results.Comments + "`r`nName: " + $valueName)
$Results.Comments = ($Results.Comments + "`r`nValue: " + ($key.$valueName | ForEach-Object { ("`r`n`t" + $_) }))

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-46473 [$($Results.Status)]"

#Return results
return $Results
