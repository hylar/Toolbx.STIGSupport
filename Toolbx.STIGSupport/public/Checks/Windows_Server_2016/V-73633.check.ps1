<#
.SYNOPSIS
    This checks for compliancy on V-73633.

    The setting Domain member: Digitally encrypt or sign secure channel data (always) must be configured to Enabled.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73633"

# Initial Variables
$Results = @{
    VulnID   = "V-73633"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty 'HKLM:\\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\' -Name RequireSignOrSeal)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.RequireSignOrSeal
    if ($value -eq 1) {
        $Results.Status = "NotAFinding"
        $Results.Details = "System always encypts or signs secure data channel. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "System NOT set to always encypt or sign secure data channel! See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73633 [$($Results.Status)]"

#Return results
return $Results
