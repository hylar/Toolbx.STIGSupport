<#
.SYNOPSIS
    This checks for compliancy on V-36736.

    The system must query the certification authority to determine whether a public key certificate has been revoked before accepting the certificate for authentication purposes.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-36736"

# Initial Variables
$Results = @{
    VulnID   = "V-36736"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
#CHECK IS WIP
$Results.Details = "Verify the system has software installed and running that provides certificate validation and revocation checking."

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-36736 [$($Results.Status)]"

#Return results
return $Results
