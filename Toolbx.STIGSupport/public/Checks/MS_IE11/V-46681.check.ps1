<#
.SYNOPSIS
    This checks for compliancy on V-46681.

    Protected Mode must be enforced (Internet zone).

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-46681"

# Initial Variables
$Results = @{
    VulnID   = "V-46681"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
[string]$keyPath = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
[string]$valueName = "2500"
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
        $Results.Details = "$valueName is set to $value, indicating protected mode is enforced for Internet Zone. See comments for details."

    }
    else {

        $Results.Status = "Open"
        $Results.Details = "$valueName is set to $value, instead of $pass! See comments for details."

    }
}

$Results.Comments = ($key | Select-Object PSPath, PSChildName, $valueName | Out-String) -replace "`r`n`r`n", ""

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-46681 [$($Results.Status)]"

#Return results
return $Results
