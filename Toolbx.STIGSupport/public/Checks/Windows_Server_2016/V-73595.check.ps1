<#
.SYNOPSIS
    This checks for compliancy on V-73595.

    The Windows Remote Management (WinRM) client must not allow unencrypted traffic.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73595"

# Initial Variables
$Results = @{
    VulnID   = "V-73595"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty 'HKLM:\\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\' -Name AllowUnencryptedTraffic)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.AllowUnencryptedTraffic
    if ($value -eq 0) {
        $Results.Status = "NotAFinding"
        $Results.Details = "WinRM client does not allow unencrypted traffic. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "WinRM client ALLOWS unencrypted traffic! See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73595 [$($Results.Status)]"

#Return results
return $Results
