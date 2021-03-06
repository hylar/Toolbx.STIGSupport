<#
.SYNOPSIS
    This checks for compliancy on V-36735.

    The system must support automated patch management tools to facilitate flaw remediation.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-36735"

# Initial Variables
$Results = @{
    VulnID   = "V-36735"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
#CHECK IS WIP
$Results.Details = "Verify the organization has an automated process to install security-related software updates."

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-36735 [$($Results.Status)]"

#Return results
return $Results
