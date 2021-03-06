<#
.SYNOPSIS
    This checks for compliancy on V-73707.

    User Account Control approval mode for the built-in Administrator must be enabled.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73707"

# Initial Variables
$Results = @{
    VulnID   = "V-73707"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty 'HKLM:\\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\' -Name FilterAdministratorToken)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.FilterAdministratorToken
    if ($value -eq 1) {
        $Results.Status = "NotAFinding"
        $Results.Details = "User Account Control for administrators is enabled. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "User Account Control for administrators is NOT enabled! See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73707 [$($Results.Status)]"

#Return results
return $Results
