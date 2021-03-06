<#
.SYNOPSIS
    This checks for compliancy on V-36671.

    Audit data must be retained for at least one year.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-36671"

# Initial Variables
$Results = @{
    VulnID   = "V-36671"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
#CHECK IS WIP
$Results.Details = "Determine whether audit data is retained for at least one year."

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-36671 [$($Results.Status)]"

#Return results
return $Results
