<#
.SYNOPSIS
    This checks for compliancy on V-1128.

    Security configuration tools or equivalent processes must be used to configure and maintain platforms for security compliance.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-1128"

# Initial Variables
$Results = @{
    VulnID   = "V-1128"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$Results.Status = "NotAFinding"
$Results.Details = "Using DISA Windwos Security STIGs."
$Results.Comments = "STIGs are verified, reviewed, and applied manually if required."

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-1128 [$($Results.Status)]"

#Return results
return $Results
