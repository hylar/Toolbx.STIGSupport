<#
.SYNOPSIS
    This checks for compliancy on V-57637.

    The operating system must employ a deny-all, permit-by-exception policy to allow the execution of authorized software programs.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-57637"

# Initial Variables
$Results = @{
    VulnID   = "V-57637"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
#CHECK IS WIP
$Results.Details = "Verify the operating system employs a deny-all, permit-by-exception policy to allow the execution of authorized software programs. See comments for AppLocker details."
[xml]$xml=Get-AppLockerPolicy -Effective -XML
$Results.Comments = $xml.AppLockerPolicy.RuleCollection | Format-List | Out-String


Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-57637 [$($Results.Status)]"

#Return results
return $Results
