<#
.SYNOPSIS
    This checks for compliancy on V-73713.

    User Account Control must automatically deny standard user requests for elevation.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73713"

# Initial Variables
$Results = @{
    VulnID   = "V-73713"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty 'HKLM:\\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\' -Name ConsentPromptBehaviorUser)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.ConsentPromptBehaviorUser
    if ($value -eq 0) {
        $Results.Status = "NotAFinding"
        $Results.Details = "User Account Control denies user request for elevation. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "User Account Control does NOT deny user request for elevation! See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73713 [$($Results.Status)]"

#Return results
return $Results
