<#
.SYNOPSIS
    This checks for compliancy on V-73589.

    Automatically signing in the last interactive user after a system-initiated restart must be disabled.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73589"

# Initial Variables
$Results = @{
    VulnID   = "V-73589"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty 'HKLM:\\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\' -Name DisableAutomaticRestartSignOn)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.DisableAutomaticRestartSignOn
    if ($value -eq 1) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Automatic logon after restart is disabled. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Automatic logon after restart is ALLOWED. See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73589 [$($Results.Status)]"

#Return results
return $Results
