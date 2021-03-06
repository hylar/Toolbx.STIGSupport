<#
.SYNOPSIS
    This checks for compliancy on V-73545.

    AutoPlay must be turned off for non-volume devices.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73545"

# Initial Variables
$Results = @{
    VulnID   = "V-73545"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\ -Name NoAutoplayfornonVolume)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.NoAutoplayfornonVolume
    if ($value -eq 1) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Auto-play is disabled for non-volume devices. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Auto-play is unrestricted! See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73545 [$($Results.Status)]"

#Return results
return $Results
