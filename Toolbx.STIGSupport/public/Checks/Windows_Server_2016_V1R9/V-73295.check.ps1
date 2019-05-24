<#
.SYNOPSIS
    This checks for compliancy on V-73295.

    The Telnet Client must not be installed.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73295"

# Initial Variables
$Results = @{
    VulnID   = "V-73295"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$role=Get-WindowsFeature | ?{$_.DisplayName -eq "Telnet Client"}
if($role.Installed -eq 0){
    $Results.Status="NotAFinding"
}else{
    $Results.Status="Open"
}
$Results.Details=$role

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73295 [$($Results.Status)]"

#Return results
return $Results
