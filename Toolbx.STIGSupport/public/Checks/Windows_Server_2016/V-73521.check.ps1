<#
.SYNOPSIS
    This checks for compliancy on V-73521.

    Early Launch Antimalware, Boot-Start Driver Initialization Policy must prevent boot drivers identified as bad.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73521"

# Initial Variables
$Results = @{
    VulnID   = "V-73521"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\ -Name DriverLoadPolicy)
if (!$key) {
    $Results.Details = "Registry key was not found."
    $Results.Status = "NotAFinding"
}
else {
    [int]$value = $key.DriverLoadPolicy
    if ($value -eq 1 -or $value -eq 3 -or $value -eq 8) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Boot-Start driver initialization does not allow bad. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Boot-Start driver initialization DOES allow bad! See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73521 [$($Results.Status)]"

#Return results
return $Results
