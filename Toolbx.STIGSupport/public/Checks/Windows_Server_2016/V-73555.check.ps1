<#
.SYNOPSIS
    This checks for compliancy on V-73555.

    The Security event log size must be configured to 196608 KB or greater.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73555"

# Initial Variables
$Results = @{
    VulnID   = "V-73555"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\ -Name MaxSize)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.MaxSize
    if ($value -ge 196608) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Security event log is configured to 196608 KB or greater. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Security event log is NOT configured correctly! See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73555 [$($Results.Status)]"

#Return results
return $Results
