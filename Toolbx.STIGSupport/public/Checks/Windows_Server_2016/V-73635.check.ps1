<#
.SYNOPSIS
    This checks for compliancy on V-73635.

    The setting Domain member: Digitally encrypt secure channel data (when possible) must be configured to enabled.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73635"

# Initial Variables
$Results = @{
    VulnID   = "V-73635"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty 'HKLM:\\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\' -Name SealSecureChannel)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.SealSecureChannel
    if ($value -eq 1) {
        $Results.Status = "NotAFinding"
        $Results.Details = "System encypts secure data channel whenever possible. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "System does NOT enforce encypting secure data channel when possible! See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73635 [$($Results.Status)]"

#Return results
return $Results
