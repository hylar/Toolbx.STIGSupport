<#
.SYNOPSIS
    This checks for compliancy on V-57719.

    The operating system must, at a minimum, off-load audit records of interconnected systems in real time and off-load standalone systems weekly.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-57719"

# Initial Variables
$Results = @{
    VulnID   = "V-57719"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$Results.Details = "Verify the operating system, at a minimum, off-loads audit records of interconnected systems in real time and off-loads standalone systems weekly."

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-57719 [$($Results.Status)]"

#Return results
return $Results
