<#
.SYNOPSIS
    This checks for compliancy on V-36670.

    Audit data must be reviewed on a regular basis.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-36670"

# Initial Variables
$Results = @{
    VulnID   = "V-36670"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
#CHECK IS WIP
$Results.Details = "Determine whether audit logs are reviewed on a predetermined schedule."

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-36670 [$($Results.Status)]"

#Return results
return $Results
