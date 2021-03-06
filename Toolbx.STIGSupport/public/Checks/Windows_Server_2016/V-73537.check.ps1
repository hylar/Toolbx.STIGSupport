<#
.SYNOPSIS
    This checks for compliancy on V-73537.

    Users must be prompted to authenticate when the system wakes from sleep (on battery).

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73537"

# Initial Variables
$Results = @{
    VulnID   = "V-73537"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\' -Name DCSettingIndex)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.DCSettingIndex
    if ($value -eq 1) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Users are required to enter credentials when computer wakes (on battery). See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Users are NOT required to enter credentials when computer wakes (on battery)! See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73537 [$($Results.Status)]"

#Return results
return $Results
