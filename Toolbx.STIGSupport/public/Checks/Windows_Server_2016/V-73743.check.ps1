<#
.SYNOPSIS
    This checks for compliancy on V-73743.

    The Back up files and directories user right must only be assigned to the Administrators group.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73743"

# Initial Variables
$Results = @{
    VulnID   = "V-73743"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$right = $PreCheck.userRights -match "SeBackupPrivilege"
if (!$right) {
    $Results.Details = "Unable to find entry in user rights!"
    $Results.Status = "Open"
}
else {
    [string]$value = $right.Accountlist
    if (($value -replace "Administrators", '' -replace " ", "").Length -eq 0) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Verified back up files and directories right is only given to Administrators. See comments for details."
        $Results.Comments = ($right | Out-String)
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Back up files and directories right contains more users/groups than Administrators; Please review! See comments for details."
        $Results.Comments = ($right | Out-String)
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73743 [$($Results.Status)]"

#Return results
return $Results
