<#
.SYNOPSIS
    This checks for compliancy on V-1168.

    Members of the Backup Operators group must be documented.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-1168"

# Initial Variables
$Results = @{
    VulnID   = "V-1168"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$members = 1
$members = Get-LocalGroupMember "Backup Operators"
if ($members.Length -eq 0) {
    $Results.Status = "Not_Applicable"
    $Results.Details = "No users or groups are members of the Backup Operators group."
}
else {
    $Results.Status = "Open"
    $Results.Details = "There are members of the Backup Operators group, please review!. See comments for details."
    $Results.Comments = $members | Format-List | Out-String
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-1168 [$($Results.Status)]"

#Return results
return $Results
