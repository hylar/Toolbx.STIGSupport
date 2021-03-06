<#
.SYNOPSIS
    This checks for compliancy on V-73571.

    Remote Desktop Services must always prompt a client for passwords upon connection.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73571"

# Initial Variables
$Results = @{
    VulnID   = "V-73571"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty 'HKLM:\\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' -Name fPromptForPassword)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.fPromptForPassword
    if ($value -eq 1) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Remote Desktop Services always prompt for password. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Remote Desktop Services NOT set to always prompt for password. See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73571 [$($Results.Status)]"

#Return results
return $Results
