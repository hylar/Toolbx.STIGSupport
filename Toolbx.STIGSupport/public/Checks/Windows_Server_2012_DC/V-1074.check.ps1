<#
.SYNOPSIS
    This checks for compliancy on V-1074.

    The Windows 2012 / 2012 R2 system must use an anti-virus program.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-1074"

# Initial Variables
$Results = @{
    VulnID   = "V-1074"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check


Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-1074 [$($Results.Status)]"

#Return results
return $Results
