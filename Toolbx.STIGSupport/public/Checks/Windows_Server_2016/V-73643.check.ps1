<#
.SYNOPSIS
    This checks for compliancy on V-73643.

    Windows Server 2016 must be configured to require a strong session key.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73643"

# Initial Variables
$Results = @{
    VulnID   = "V-73643"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty 'HKLM:\\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\' -Name RequireStrongKey)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.RequireStrongKey
    if ($value -eq 1) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Strong session key is required. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Strong session key NOT required! See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73643 [$($Results.Status)]"

#Return results
return $Results
