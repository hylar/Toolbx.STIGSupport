<#
.SYNOPSIS
    This checks for compliancy on V-73501.

    Source routing must be configured to the highest protection level to prevent Internet Protocol (IP) source routing.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73501"

# Initial Variables
$Results = @{
    VulnID   = "V-73501"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\ -Name DisableIPSourceRouting)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}else {
    [int]$value = $key.DisableIPSourceRouting
    if ($value -eq 2) {
        $Results.Status = "NotAFinding"
        $Results.Details = "IP source routing is at highest protection level. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "IP source routing is NOT at highest protection level. See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73501 [$($Results.Status)]"

#Return results
return $Results
