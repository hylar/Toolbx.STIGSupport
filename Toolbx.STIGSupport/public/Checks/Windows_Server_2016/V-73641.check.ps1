<#
.SYNOPSIS
    This checks for compliancy on V-73641.

    The maximum age for machine account passwords must be configured to 30 days or less.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73641"

# Initial Variables
$Results = @{
    VulnID   = "V-73641"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty 'HKLM:\\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\' -Name MaximumPasswordAge)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.MaximumPasswordAge
    if ($value -le 30) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Maximum machine account password age is $value days. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Maximum machine account password age is NOT 30 days or less. See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73641 [$($Results.Status)]"

#Return results
return $Results
