<#
.SYNOPSIS
    This checks for compliancy on V-36661.

    Policy must require application account passwords be at least 15 characters in length.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-36661"

# Initial Variables
$Results = @{
    VulnID   = "V-36661"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
#CHECK IS WIP
$Results.Details = "Verify the site has a policy to ensure passwords for manually managed application/service accounts are at least 15 characters in length."

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-36661 [$($Results.Status)]"

#Return results
return $Results
