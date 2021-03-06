<#
.SYNOPSIS
    This checks for compliancy on V-36672.

    Audit records must be backed up onto a different system or media than the system being audited.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-36672"

# Initial Variables
$Results = @{
    VulnID   = "V-36672"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
#CHECK IS WIP
$Results.Details = "Determine if a process to back up log data to a different system or media than the system being audited has been implemented."

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-36672 [$($Results.Status)]"

#Return results
return $Results
