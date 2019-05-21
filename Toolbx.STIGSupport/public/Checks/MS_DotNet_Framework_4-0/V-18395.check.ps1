<#
.SYNOPSIS
    This checks for compliancy on V-####

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "Checking - V-18395"

# Initial Variables
$Results = @{
    VulnID   = "V-18395"
    RuleID   = ""
    Details  = "This was a test of the details"
    Comments = "This was a test of the comments"
    Status   = "Open"
}

#Perform necessary check


Write-Verbose "Completed Checking - V-18395 [$($Results.Status)]"

#Return results
return $Results