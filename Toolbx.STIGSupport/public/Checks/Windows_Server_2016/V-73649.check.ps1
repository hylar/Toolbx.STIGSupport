<#
.SYNOPSIS
    This checks for compliancy on V-73649.

    The Windows dialog box title for the legal banner must be configured with the appropriate text.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73649"

# Initial Variables
$Results = @{
    VulnID   = "V-73649"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty 'HKLM:\\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\' -Name LegalNoticeCaption)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [string]$value = $key.LegalNoticeCaption
    if ($value -eq "DoD Notice and Consent Banner" -or $value -eq "US Department of Defense Warning Statement") {
        $Results.Status = "NotAFinding"
        $Results.Details = "Legal banner is configured as specified ('$value'). See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Legal banner does not match the expected values! See comments for details."
        $Results.Comments = $key | Out-String
    }
}
Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73649 [$($Results.Status)]"

#Return results
return $Results
