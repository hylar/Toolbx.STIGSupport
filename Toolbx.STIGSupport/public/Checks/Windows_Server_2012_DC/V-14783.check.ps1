<#
.SYNOPSIS
    This checks for compliancy on V-14783.

    Separate, NSA-approved (Type 1) cryptography must be used to protect the directory data-in-transit for directory service implementations at a classified confidentiality level when replication data traverses a network cleared to a lower level than the data.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-14783"

# Initial Variables
$Results = @{
    VulnID   = "V-14783"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
#CHECK IS WIP
$Results.Details = "With the assistance of the SA, NSO, or network reviewer as required, review the site network diagram(s) or documentation to determine the level of classification for the network(s) over which replication data is transmitted."

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-14783 [$($Results.Status)]"

#Return results
return $Results
