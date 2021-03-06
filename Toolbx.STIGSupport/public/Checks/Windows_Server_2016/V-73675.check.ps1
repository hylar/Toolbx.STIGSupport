<#
.SYNOPSIS
    This checks for compliancy on V-73675.

    Anonymous access to Named Pipes and Shares must be restricted.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73675"

# Initial Variables
$Results = @{
    VulnID   = "V-73675"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty 'HKLM:\\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\' -Name RestrictNullSessAccess)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.RestrictNullSessAccess
    if ($value -eq 1) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Anonymous access to Named Pipes and Shares are restricted. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Anonymous access to Named Pipes and Shares are NOT restricted! See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73675 [$($Results.Status)]"

#Return results
return $Results
