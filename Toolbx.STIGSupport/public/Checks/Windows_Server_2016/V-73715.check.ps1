<#
.SYNOPSIS
    This checks for compliancy on V-73715.

    User Account Control must be configured to detect application installations and prompt for elevation.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73715"

# Initial Variables
$Results = @{
    VulnID   = "V-73715"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty 'HKLM:\\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\' -Name EnableInstallerDetection)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.EnableInstallerDetection
    if ($value -eq 1) {
        $Results.Status = "NotAFinding"
        $Results.Details = "User Account Control detects installations and prompts for elevation. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "User Account Control does NOT detect installations and prompt for elevation. See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73715 [$($Results.Status)]"

#Return results
return $Results
