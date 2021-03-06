<#
.SYNOPSIS
    This checks for compliancy on V-36658.

    Users with administrative privilege must be documented.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-36658"

# Initial Variables
$Results = @{
    VulnID   = "V-36658"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
#CHECK IS WIP
$Results.Details = "Review the necessary documentation that identifies the members of the Administrators group."

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-36658 [$($Results.Status)]"

#Return results
return $Results
