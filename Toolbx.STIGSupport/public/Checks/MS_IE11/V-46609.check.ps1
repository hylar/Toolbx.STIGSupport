<#
.SYNOPSIS
    This checks for compliancy on V-46609.

    Configuring History setting must be set to 40 days.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-46609"

# Initial Variables
$Results = @{
    VulnID   = "V-46609"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
[string]$keyPath = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Control Panel"
[string]$valueName = "History"
[int]$pass = 1

$key = (Get-ItemProperty $keyPath -Name $valueName -ErrorAction SilentlyContinue)

[string]$keyPath2 = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Url History"
[string]$valueName2 = "DaysToKeep"
[int]$pass2 = 40

$key2 = (Get-ItemProperty $keyPath2 -Name $valueName2 -ErrorAction SilentlyContinue)

if (!$key) {

    $Results.Details = "Registry value at $keyPath with name $valueName was not found!"
    $Results.Status = "Open"

}
elseif (!$key2){

    $Results.Details += "`r`nRegistry value at $keyPath2 with name $valueName2 was not found!"
    $Results.Status = "Open"

}
else {

    [int]$value = $key.$valueName

    if ($value -eq $pass) {

        $Results.Status = "NotAFinding"
        $Results.Details = "$valueName is set to $value. See comments for details."

    }
    else {

        $Results.Status = "Open"
        $Results.Details = "$valueName is set to $value, instead of $pass! See comments for details."

    }

    [int]$value2 = $key2.$valueName2

    if ($value2 -eq $pass2) {

        $Results.Details += "`r`n$valueName2 is set to $value2. See comments for details."

    }
    else {

        $Results.Status = "Open"
        $Results.Details += "`r`n$valueName2 is set to $value2, instead of $pass2! See comments for details."

    }
}

$Results.Comments = "Path: "+($key.PSPath -replace [regex]::escape("Microsoft.PowerShell.Core\Registry::"),"")
$Results.Comments = ($Results.Comments+"`r`nName: "+$valueName)
$Results.Comments = ($Results.Comments+"`r`nValue: "+($key.$valueName | ForEach-Object{ ("`r`n`t"+$_) }))
$Results.Comments += ($key2 | Select-Object PSPath,PSChildName,$valueName2 | Out-String) -replace "`r`n`r`n",""

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-46609 [$($Results.Status)]"

#Return results
return $Results
