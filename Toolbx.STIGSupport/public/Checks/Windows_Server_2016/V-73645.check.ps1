<#
.SYNOPSIS
    This checks for compliancy on V-73645.

    The machine inactivity limit must be set to 15 minutes, locking the system with the screen saver.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73645"

# Initial Variables
$Results = @{
    VulnID   = "V-73645"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty 'HKLM:\\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\' -Name InactivityTimeoutSecs)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.InactivityTimeoutSecs
    if ($value -le 900) {
        $Results.Status = "NotAFinding"
        $Results.Details = "System set to lock after $value seconds of inactivity. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "System NOT set to lock after 15 minutes or less! See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73645 [$($Results.Status)]"

#Return results
return $Results
