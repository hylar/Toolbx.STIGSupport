<#
.SYNOPSIS
    This checks for compliancy on V-75915.

    Orphaned security identifiers (SIDs) must be removed from user rights on Windows 2012 / 2012 R2.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-75915"

# Initial Variables
$Results = @{
    VulnID   = "V-75915"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$test = $PreCheck.userRights | Where-Object {$_.Accountlist -match "Admin"}
$SIDs = $PreCheck.userRights | Where-Object {$_.Accountlist -match "S-1-"}
if (!$test) {
    $Results.Status = "Not_Reviewed"
    $Results.Details = "Could not analyze User Rights assignments; Please review!"
}
elseif ($test -and !$SIDs) {
    $Results.Status = "NotAFinding"
    $Results.Details = "No unresolved SIDs found in User Rights assignments. See comments for details."
}
else {
    $Results.Status = "Open"
    $Results.Details = "Found unresolved SIDs found in User Rights assignments; Please review! See comments for details."
}
$Results.Comments = $PreCheck.userRights | Format-List | Out-String

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-75915 [$($Results.Status)]"

#Return results
return $Results
