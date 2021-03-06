<#
.SYNOPSIS
    This checks for compliancy on V-73511.

    Command line data must be included in process creation events.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73511"

# Initial Variables
$Results = @{
    VulnID   = "V-73511"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ -Name ProcessCreationIncludeCmdLine_Enabled)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.ProcessCreationIncludeCmdLine_Enabled
    if ($value -eq 1) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Command line data is included in process creation events. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Command line data is NOT included in process creation events! See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73511 [$($Results.Status)]"

#Return results
return $Results
