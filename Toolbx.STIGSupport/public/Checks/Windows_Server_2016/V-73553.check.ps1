<#
.SYNOPSIS
    This checks for compliancy on V-73553.

    The Application event log size must be configured to 32768 KB or greater.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73553"

# Initial Variables
$Results = @{
    VulnID   = "V-73553"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\ -Name MaxSize)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.MaxSize
    if ($value -ge 32768) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Application event log is configured to 32768 KB or greater. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Application event log is NOT configured correctly! See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73553 [$($Results.Status)]"

#Return results
return $Results
