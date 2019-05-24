<#
.SYNOPSIS
    This checks for compliancy on V-73559.

    Windows SmartScreen must be enabled.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73559"

# Initial Variables
$Results = @{
    VulnID   = "V-73559"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\ -Name EnableSmartScreen)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.EnableSmartScreen
    if ($value -eq 1) {
        $Results.Details = "$key"
        $Results.Status = "NotAFinding"
    }
    else {
        $Results.Details = "$key"
        $Results.Status = "Open"
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73559 [$($Results.Status)]"

#Return results
return $Results
