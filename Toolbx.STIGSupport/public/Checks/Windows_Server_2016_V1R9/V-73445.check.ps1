<#
.SYNOPSIS
    This checks for compliancy on V-73445.

    Windows Server 2016 must be configured to audit Logon/Logoff - Account Lockout failures.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73445"

# Initial Variables
$Results = @{
    VulnID   = "V-73445"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$line=$logonOff -match "Account Lockout"
if($line -like "*Failure*"){
    $Results.Status="NotAFinding"
}else{
    $Results.Status="Open"
}
$Results.Details="Auditpol.exe reports: $line"

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73445 [$($Results.Status)]"

#Return results
return $Results
