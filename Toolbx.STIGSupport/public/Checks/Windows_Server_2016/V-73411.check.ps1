<#
.SYNOPSIS
    This checks for compliancy on V-73411.

    Event Viewer must be protected from unauthorized modification and deletion.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73411"

# Initial Variables
$Results = @{
    VulnID   = "V-73411"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$details = (Get-Acl -Path $env:SystemRoot\System32\Eventvwr.exe).Access
$temp = ($details.IdentityReference).Value | Out-String
$temp = $temp -replace "`r", "" -replace "`n", ""
if ($temp -eq 'NT AUTHORITY\SYSTEMBUILTIN\AdministratorsBUILTIN\UsersNT SERVICE\TrustedInstallerAPPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGESAPPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES') {
    $Results.Status = "NotAFinding"
}else {
    $Results.Status = "Open"
}
$temp = ($details.FileSystemRights) | Out-String
$temp = $temp -replace "`r", "" -replace "`n", ""
if ($Results.Status -eq "NotAFinding" -and $temp -eq 'ReadAndExecute, SynchronizeReadAndExecute, SynchronizeReadAndExecute, SynchronizeFullControlReadAndExecute, SynchronizeReadAndExecute, Synchronize') {
    $Results.Details = "Permissions to Event Viewer are as expected; Only privileged accounts have access. See comments for details."
}else {
    $Results.Status = "Open"
    $Results.Details = "Permissions to Event Viewer are non-standard, please review. See comments for details."
}
$Results.Comments = $details | Select IdentityReference, FileSystemRights | Out-String

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73411 [$($Results.Status)]"

#Return results
return $Results
