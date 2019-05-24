<#
.SYNOPSIS
    This checks for compliancy on V-90359.

    Windows 2016 must be configured to audit Object Access - Other Object Access Events successes.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-90359"

# Initial Variables
$Results = @{
    VulnID   = "V-90359"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$line=$objAccess -match "Other Object Access Events"
if($line -like "*Success*"){
    $Results.Status="NotAFinding"
}else{
    $Results.Status="Open"
}
$Results.Details="Auditpol.exe reports: $line"

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-90359 [$($Results.Status)]"

#Return results
return $Results
