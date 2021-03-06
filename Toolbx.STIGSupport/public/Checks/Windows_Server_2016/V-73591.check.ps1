<#
.SYNOPSIS
    This checks for compliancy on V-73591.

    PowerShell script block logging must be enabled.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73591"

# Initial Variables
$Results = @{
    VulnID   = "V-73591"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty 'HKLM:\\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\' -Name EnableScriptBlockLogging)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.EnableScriptBlockLogging
    if ($value -eq 1) {
        $Results.Status = "NotAFinding"
        $Results.Details = "PowerShell script logging is enabled. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "PowerShell script logging is NOT enabled! See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73591 [$($Results.Status)]"

#Return results
return $Results
