<#
.SYNOPSIS
    This checks for compliancy on V-73637.

    The setting Domain member: Digitally sign secure channel data (when possible) must be configured to Enabled.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73637"

# Initial Variables
$Results = @{
    VulnID   = "V-73637"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty 'HKLM:\\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\' -Name SignSecureChannel)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.SignSecureChannel
    if ($value -eq 1) {
        $Results.Status = "NotAFinding"
        $Results.Details = "System signs secure data channel whenever possible. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "System does NOT enforce signing secure data channel when possible! See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73637 [$($Results.Status)]"

#Return results
return $Results
