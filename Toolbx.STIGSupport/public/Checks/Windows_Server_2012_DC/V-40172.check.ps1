<#
.SYNOPSIS
    This checks for compliancy on V-40172.

    Backups of system-level information must be protected.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-40172"

# Initial Variables
$Results = @{
    VulnID   = "V-40172"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
#CHECK IS WIP
$Results.Details = "Determine if system-level information backups are protected from destruction and stored in a physically secure location."

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-40172 [$($Results.Status)]"

#Return results
return $Results
