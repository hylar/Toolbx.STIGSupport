<#
.SYNOPSIS
    This checks for compliancy on V-1070.

    Server systems must be located in a controlled access area, accessible only to authorized personnel.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-1070"

# Initial Variables
$Results = @{
    VulnID   = "V-1070"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
#CHECK IS WIP
$Results.Details = "Verify servers are located in controlled access areas that are accessible only to authorized personnel."

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-1070 [$($Results.Status)]"

#Return results
return $Results
