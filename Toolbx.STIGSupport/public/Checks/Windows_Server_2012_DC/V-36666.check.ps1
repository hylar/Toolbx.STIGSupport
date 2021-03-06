<#
.SYNOPSIS
    This checks for compliancy on V-36666.

    Policy must require that system administrators (SAs) be trained for the operating systems used by systems under their control.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-36666"

# Initial Variables
$Results = @{
    VulnID   = "V-36666"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
#CHECK IS WIP
$Results.Details = "Determine whether the site has a policy that requires SAs be trained for all operating systems running on systems under their control."

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-36666 [$($Results.Status)]"

#Return results
return $Results
