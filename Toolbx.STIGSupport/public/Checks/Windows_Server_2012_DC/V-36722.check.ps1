<#
.SYNOPSIS
    This checks for compliancy on V-36722.

    Permissions for the Application event log must prevent access by nonprivileged accounts.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-36722"

# Initial Variables
$Results = @{
    VulnID   = "V-36722"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$details = (Get-Acl -Path $env:SystemRoot\System32\winevt\Logs\Application.evtx).Access
$temp = ($details.IdentityReference).Value | Out-String
$temp = $temp -replace "`r", "" -replace "`n", ""
if ($temp -eq 'NT SERVICE\EventLogNT AUTHORITY\SYSTEMBUILTIN\Administrators') {
    $Results.Status = "NotAFinding"
}
else {
    $Results.Status = "Open"
}
$temp = ($details.FileSystemRights) | Out-String
$temp = $temp -replace "`r", "" -replace "`n", ""
if ($Results.Status -eq "NotAFinding" -and $temp -eq 'FullControlFullControlFullControl') {
    $Results.Details = "Permissions to the Application event log are as expected; Only privileged accounts have access. See comments for details."
}
else {
    $Results.Status = "Open"
    $Results.Details = "Permissions to Application event log are non-standard, please review. See comments for details."
}
$Results.Comments = $details | Select IdentityReference, FileSystemRights | Out-String

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-36722 [$($Results.Status)]"

#Return results
return $Results
