<#
.SYNOPSIS
    This checks for compliancy on V-73639.

    The computer account password must not be prevented from being reset.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73639"

# Initial Variables
$Results = @{
    VulnID   = "V-73639"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty 'HKLM:\\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\' -Name DisablePasswordChange)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.DisablePasswordChange
    if ($value -eq 0) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Computer account password is able to be reset. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Computer account password is NOT able to be reset! See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73639 [$($Results.Status)]"

#Return results
return $Results
