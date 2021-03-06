<#
.SYNOPSIS
    This checks for compliancy on V-40198.

    Members of the Backup Operators group must have separate accounts for backup duties and normal operational tasks.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-40198"

# Initial Variables
$Results = @{
    VulnID   = "V-40198"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$members = Get-LocalGroup -Name "Backup Operators" | Get-LocalGroupMember
if (!$members) {
    $Results.Status = "Not_Applicable"
    $Results.Details = "The 'Backup Operators' group has no members, this check is not applicable."
}
else {
    $Results.Details = "The 'Backup Operators' group contains members, rify users with accounts in the Backup Operators group have a separate user account for backup functions and for performing normal user tasks. See comments for details."
    $Results.Comments = $Results.Status = "Not_Applicable"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-40198 [$($Results.Status)]"

#Return results
return $Results
