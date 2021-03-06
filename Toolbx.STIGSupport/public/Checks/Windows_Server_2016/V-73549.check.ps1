<#
.SYNOPSIS
    This checks for compliancy on V-73549.

    AutoPlay must be disabled for all drives.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73549"

# Initial Variables
$Results = @{
    VulnID   = "V-73549"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\ -Name NoDriveTypeAutoRun)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.NoDriveTypeAutoRun
    if ($value -eq 255) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Auto-play is disabled for all drives. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Auto-play is allowed! See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73549 [$($Results.Status)]"

#Return results
return $Results
