<#
.SYNOPSIS
    This checks for compliancy on V-57645.

    Systems requiring data at rest protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-57645"

# Initial Variables
$Results = @{
    VulnID   = "V-57645"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$Results.Details = "Verify systems that require additional protections due to factors such as inadequate physical protection or sensitivity of the data employ encryption to protect the confidentiality and integrity of all information at rest."

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-57645 [$($Results.Status)]"

#Return results
return $Results
