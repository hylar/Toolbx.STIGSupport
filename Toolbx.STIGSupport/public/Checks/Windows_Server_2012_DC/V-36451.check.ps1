<#
.SYNOPSIS
    This checks for compliancy on V-36451.

    Administrative accounts must not be used with applications that access the Internet, such as web browsers, or with potential Internet sources, such as email.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-36451"

# Initial Variables
$Results = @{
    VulnID   = "V-36451"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
#CHECK IS WIP
$Results.Details = "The organization must have a policy that prohibits administrative accounts from using applications that access the Internet, such as web browsers, or with potential Internet sources, such as email, except as necessary for local service administration."

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-36451 [$($Results.Status)]"

#Return results
return $Results
