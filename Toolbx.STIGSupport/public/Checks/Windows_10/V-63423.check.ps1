<#
.SYNOPSIS
    This checks for compliancy on V-63423.

    Passwords must, at a minimum, be 14 characters.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param(`$PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-63423"

# Initial Variables
$Results = @{
    VulnID   = "V-63423"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
[string]$keyPath = "HKLM:\PATH"
[string]$valueName = "VALUENAME"
[int]$pass = PASS
$key = (Get-ItemProperty $keyPath -Name $valueName)
if (!$key) {
    $Results.Details = "Registry value at $keyPath with name $valueName was not found!"
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
        $Results.Details = "$valueName is set to $value! See comments for details."
    }
}
$Results.Comments = $key | Select PSPath,$valueName | Out-String

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-63423 [$($Results.Status)]"

#Return results
return $Results
