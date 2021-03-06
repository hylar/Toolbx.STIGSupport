<#
.SYNOPSIS
    This checks for compliancy on V-40173.

    System-related documentation must be backed up in accordance with local recovery time and recovery point objectives.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-40173"

# Initial Variables
$Results = @{
    VulnID   = "V-40173"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
#CHECK IS WIP
$Results.Details = "Determine whether system-related documentation is backed up in accordance with local recovery time and recovery point objectives."

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-40173 [$($Results.Status)]"

#Return results
return $Results
