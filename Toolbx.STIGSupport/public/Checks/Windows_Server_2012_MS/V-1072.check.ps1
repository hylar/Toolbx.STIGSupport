<#
.SYNOPSIS
    This checks for compliancy on V-1072.

    Shared user accounts must not be permitted on the system.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-1072"

# Initial Variables
$Results = @{
    VulnID   = "V-1072"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
#CHECK IS WIP
$Results.Details = "Determine whether any shared accounts exist. If no shared accounts exist, this is NA."

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-1072 [$($Results.Status)]"

#Return results
return $Results
