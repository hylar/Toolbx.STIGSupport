<#
.SYNOPSIS
    This checks for compliancy on V-73661.

    The setting Microsoft network server: Digitally sign communications (always) must be configured to Enabled.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73661"

# Initial Variables
$Results = @{
    VulnID   = "V-73661"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty 'HKLM:\\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\' -Name RequireSecuritySignature)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.RequireSecuritySignature
    if ($value -eq 1) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Server is configured to always digitally sign communications. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Digitally signing of all communications is NOT enforced! See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73661 [$($Results.Status)]"

#Return results
return $Results
