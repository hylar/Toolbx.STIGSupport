<#
.SYNOPSIS
    This checks for compliancy on V-57653.

    Windows 2012 / 2012 R2 must automatically remove or disable temporary user accounts after 72 hours.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-57653"

# Initial Variables
$Results = @{
    VulnID   = "V-57653"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$Results.Details = "Determine if temporary user accounts are used and identify any that exist. If none exist, this is NA."

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-57653 [$($Results.Status)]"

#Return results
return $Results
