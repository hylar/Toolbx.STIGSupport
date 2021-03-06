<#
.SYNOPSIS
    This checks for compliancy on V-73807.

    The Smart Card removal option must be configured to Force Logoff or Lock Workstation.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73807"

# Initial Variables
$Results = @{
    VulnID   = "V-73807"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty 'HKLM:\\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\' -Name scremoveoption)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.scremoveoption
    if ($value -eq 1 ) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Actions on smartcard removal set to 'Lock Workstation.' See comments for details."
        $Results.Comments = $key | Out-String
    }
    elseif ($value -eq 2 ) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Actions on smartcard removal set to 'Force Loggoff.' See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Smartcard removal policy not configured to lock or logoff! See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73807 [$($Results.Status)]"

#Return results
return $Results
