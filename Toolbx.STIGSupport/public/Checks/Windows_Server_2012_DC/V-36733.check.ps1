<#
.SYNOPSIS
    This checks for compliancy on V-36733.

    User-level information must be backed up in accordance with local recovery time and recovery point objectives.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-36733"

# Initial Variables
$Results = @{
    VulnID   = "V-36733"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
#CHECK IS WIP
$Results.Details = "Determine whether user-level information is backed up in accordance with local recovery time and recovery point objectives."

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-36733 [$($Results.Status)]"

#Return results
return $Results
