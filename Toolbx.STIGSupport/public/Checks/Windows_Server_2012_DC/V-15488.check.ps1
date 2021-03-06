<#
.SYNOPSIS
    This checks for compliancy on V-15488.

    Active directory user accounts, including administrators, must be configured to require the use of a Common Access Card (CAC), PIV-compliant hardware token, or Alternate Logon Token (ALT) for user authentication.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-15488"

# Initial Variables
$Results = @{
    VulnID   = "V-15488"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
#CHECK IS WIP - Need to understand exceptions better.
$users = Get-ADUser -Properties SmartcardLogonRequired -Filter {(Enabled -eq $True) -and (SmartcardLogonRequired -eq $False)}
#$usersFilter = $users | Where-Object {$_.DistinguishedName -match "User" -or $_.DistinguishedName -match "Admin" -and $_.DistinguishedName -notmatch "Service Account"}
$usersFilter = $users# | Where-Object {$_.DistinguishedName -notmatch "Service Account"}
if ($usersFilter.Length -eq 0) {
    $Results.Status = "NotAFinding"
    $Results.Details = "Unable to find any accounts that are not smartcard enforced in non-service account OUs."
}
else {
    $Results.Status = "Open"
    $Results.Details = "Found un-enforced accounts; Please review! See comments for details."
    $Results.Comments = $users | Select-Object SamAccountName, DistinguishedName, SmartcardLogonRequired | Format-List | Out-String
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-15488 [$($Results.Status)]"

#Return results
return $Results
