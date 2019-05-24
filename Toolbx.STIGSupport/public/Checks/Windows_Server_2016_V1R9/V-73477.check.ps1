<#
.SYNOPSIS
    This checks for compliancy on V-73477.

    Windows Server 2016 must be configured to audit System - Other System Events successes.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73477"

# Initial Variables
$Results = @{
    VulnID   = "V-73477"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$line=$system -match "Other System Events"
if($line -like "*Success*"){
    $Results.Status="NotAFinding"
}else{
    $Results.Status="Open"
}
$Results.Details="Auditpol.exe reports: $line"

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73477 [$($Results.Status)]"

#Return results
return $Results
