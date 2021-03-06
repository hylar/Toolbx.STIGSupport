<#
.SYNOPSIS
    This checks for compliancy on V-73507.

    Insecure logons to an SMB server must be disabled.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73507"

# Initial Variables
$Results = @{
    VulnID   = "V-73507"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\ -Name AllowInsecureGuestAuth)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.AllowInsecureGuestAuth
    if ($value -eq 0) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Insecure logons are disabled. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Insecure logons are NOT disabled. See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73507 [$($Results.Status)]"

#Return results
return $Results
