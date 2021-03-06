<#
.SYNOPSIS
    This checks for compliancy on V-73719.

    User Account Control must run all administrators in Admin Approval Mode, enabling UAC.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73719"

# Initial Variables
$Results = @{
    VulnID   = "V-73719"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty 'HKLM:\\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\' -Name EnableLUA)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.EnableLUA
    if ($value -eq 1) {
        $Results.Status = "NotAFinding"
        $Results.Details = "User Account Control runs in Admin Approval Mode. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "User Account Control does NOT run in Admin Approval Mode! See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73719 [$($Results.Status)]"

#Return results
return $Results
