<#
.SYNOPSIS
    This checks for compliancy on V-73577.

    Attachments must be prevented from being downloaded from RSS feeds.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73577"

# Initial Variables
$Results = @{
    VulnID   = "V-73577"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty 'HKLM:\\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds\' -Name DisableEnclosureDownload)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.DisableEnclosureDownload
    if ($value -eq 1) {
        $Results.Status = "NotAFinding"
        $Results.Details = "RSS feed attachment downloads are disabled. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "RSS feed attachment downloads are ALLOWED! See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73577 [$($Results.Status)]"

#Return results
return $Results
