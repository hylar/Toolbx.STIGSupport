<#
.SYNOPSIS
    This checks for compliancy on V-78125.

    The Server Message Block (SMB) v1 protocol must be disabled on the SMB client.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-78125"

# Initial Variables
$Results = @{
    VulnID   = "V-78125"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty 'HKLM:\\SYSTEM\CurrentControlSet\Services\mrxsmb10\' -Name Start)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.Start
    if ($value -eq 4) {
        $Results.Status = "NotAFinding"
        $Results.Details = "SMB v1 is disabled on client. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "SMB v1 is NOT disabled on client! See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-78125 [$($Results.Status)]"

#Return results
return $Results
