<#
.SYNOPSIS
    This checks for compliancy on V-73709.

    UIAccess applications must not be allowed to prompt for elevation without using the secure desktop.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73709"

# Initial Variables
$Results = @{
    VulnID   = "V-73709"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty 'HKLM:\\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\' -Name EnableUIADesktopToggle)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.EnableUIADesktopToggle
    if ($value -eq 0) {
        $Results.Status = "NotAFinding"
        $Results.Details = "UIAccess applications must use secure desktop for elevation. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "UIAccess applications not required to use secure desktop for elevation! See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73709 [$($Results.Status)]"

#Return results
return $Results
