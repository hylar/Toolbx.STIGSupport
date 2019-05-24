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
        $Results.Details = "$key"
        $Results.Status = "NotAFinding"
    }
    else {
        $Results.Details = "$key"
        $Results.Status = "Open"
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73511 [$($Results.Status)]"

#Return results
return $Results
