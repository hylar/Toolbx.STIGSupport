<#
.SYNOPSIS
    This checks for compliancy on V-63717.

    The use of a hardware security device with Windows Hello for Business must be enabled.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-63717"

# Initial Variables
$Results = @{
    VulnID   = "V-63717"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
[string]$keyPath = "HKLM:\PATH"
[string]$valueName = "VALUENAME"
[int]$pass = PASS
$key = (Get-ItemProperty $keyPath -Name $valueName -ErrorAction SilentlyContinue)
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
        $Results.Details = "$valueName is set to $value, instead of $pass! See comments for details."
    }
}
$Results.Comments = $key | Select PSPath,PSChildName,$valueName | Out-String

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-63717 [$($Results.Status)]"

#Return results
return $Results
