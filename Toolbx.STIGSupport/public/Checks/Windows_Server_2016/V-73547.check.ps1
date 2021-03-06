<#
.SYNOPSIS
    This checks for compliancy on V-73547.

    The default AutoRun behavior must be configured to prevent AutoRun commands.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73547"

# Initial Variables
$Results = @{
    VulnID   = "V-73547"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\ -Name NoAutorun)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.NoAutorun
    if ($value -eq 1) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Auto-run is disabled. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Auto-run is allowed! See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73547 [$($Results.Status)]"

#Return results
return $Results
