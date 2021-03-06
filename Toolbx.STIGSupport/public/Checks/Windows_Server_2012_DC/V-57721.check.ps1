<#
.SYNOPSIS
    This checks for compliancy on V-57721.

    Event Viewer must be protected from unauthorized modification and deletion.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-57721"

# Initial Variables
$Results = @{
    VulnID   = "V-57721"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$details = (Get-Acl -Path $env:SystemRoot\System32\Eventvwr.exe).Access
$fail = 0
$failNames = @()
foreach ($item in $details) {
    if (
        ($item.IdentityReference -eq "NT AUTHORITY\SYSTEM" -or
        $item.IdentityReference -eq "BUILTIN\Administrators" -or
        $item.IdentityReference -eq "BUILTIN\Users" -or
        $item.IdentityReference -eq "APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES") -and
        $item.FileSystemRights -eq "ReadAndExecute, Synchronize"
    ) {
        #Good
    }
    elseif (
        $item.IdentityReference -eq "NT SERVICE\TrustedInstaller" -and
        $item.FileSystemRights -eq "FullControl"
    ) {
        #Good
    }
    else {
        $fail = 1
        $failNames += $item | Select-Object IdentityReference,FileSystemRights | Format-List | Out-String
    }
}
if ($fail -eq 0) {
    $Results.Status = "NotAFinding"
    $Results.Details = "Permissions to Event Viewer are as expected; Only privileged accounts have access. See comments for details."
}else {
    $Results.Status = "Open"
    $Results.Details = "Permissions to Event Viewer are non-standard, please review. See comments for details."
    $Results.Comments = "-=Unexpected Rights=-`r`n"
    $Results.Comments += $failNames
}
$Results.Comments += "-=All Rights=-`r`n"
$Results.Comments += $details | Select IdentityReference, FileSystemRights | Format-Table | Out-String

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-57721 [$($Results.Status)]"

#Return results
return $Results
