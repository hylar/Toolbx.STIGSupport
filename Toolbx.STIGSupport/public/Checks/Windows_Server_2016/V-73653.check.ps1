<#
.SYNOPSIS
    This checks for compliancy on V-73653.

    The setting Microsoft network client: Digitally sign communications (always) must be configured to Enabled.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73653"

# Initial Variables
$Results = @{
    VulnID   = "V-73653"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty 'HKLM:\\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\' -Name RequireSecuritySignature)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.RequireSecuritySignature
    if ($value -eq 1) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Network client always digitally signs communications. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Network client NOT set to always digitally sign communications! See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73653 [$($Results.Status)]"

#Return results
return $Results
