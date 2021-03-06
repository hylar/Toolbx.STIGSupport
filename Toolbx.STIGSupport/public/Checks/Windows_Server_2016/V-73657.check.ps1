<#
.SYNOPSIS
    This checks for compliancy on V-73657.

    Unencrypted passwords must not be sent to third-party Server Message Block (SMB) servers.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73657"

# Initial Variables
$Results = @{
    VulnID   = "V-73657"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty 'HKLM:\\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\' -Name EnablePlainTextPassword)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.EnablePlainTextPassword
    if ($value -eq 0) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Unencrypted passwords not allowed to be sent to third-party SMB servers. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Unencrypted passwords are not allowed to be sent to third-party SMB servers. See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73657 [$($Results.Status)]"

#Return results
return $Results
