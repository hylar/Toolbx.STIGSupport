<#
.SYNOPSIS
    This checks for compliancy on V-73493.

    The display of slide shows on the lock screen must be disabled.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73493"

# Initial Variables
$Results = @{
    VulnID   = "V-73493"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization\ -Name NoLockScreenSlideshow)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.NoLockScreenSlideshow
    if ($value -eq 1) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Lock screen slideshow is disabled. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Lock screen slideshow is NOT disabled. See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73493 [$($Results.Status)]"

#Return results
return $Results
