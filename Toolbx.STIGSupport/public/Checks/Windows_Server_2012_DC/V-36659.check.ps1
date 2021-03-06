<#
.SYNOPSIS
    This checks for compliancy on V-36659.

    Users with Administrative privileges must have separate accounts for administrative duties and normal operational tasks.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-36659"

# Initial Variables
$Results = @{
    VulnID   = "V-36659"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
#CHECK IS WIP
$Results.Details = "Verify each user with administrative privileges has been assigned a unique administrative account separate from their standard user account."

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-36659 [$($Results.Status)]"

#Return results
return $Results
