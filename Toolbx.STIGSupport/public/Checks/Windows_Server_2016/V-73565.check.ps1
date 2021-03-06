<#
.SYNOPSIS
    This checks for compliancy on V-73565.

    File Explorer shell protocol must run in protected mode.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73565"

# Initial Variables
$Results = @{
    VulnID   = "V-73565"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\ -Name PreXPSP2ShellProtocolBehavior)
if (!$key) {
    $Results.Details = "Registry key was not found."
    $Results.Status = "NotAFinding"
}
else {
    [int]$value = $key.PreXPSP2ShellProtocolBehavior
    if ($value -eq 0) {
        $Results.Status = "NotAFinding"
        $Results.Details = "File Explorer shell runs in protected mode. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "File Explorer shell NOT configured to run in protected mode. See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73565 [$($Results.Status)]"

#Return results
return $Results
