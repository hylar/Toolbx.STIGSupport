<#
.SYNOPSIS
    This checks for compliancy on V-73287.

    The Fax Server role must not be installed.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73287"

# Initial Variables
$Results = @{
    VulnID   = "V-73287"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$role=Get-WindowsFeature | ?{$_.DisplayName -eq "Fax Server"}
if($role.Installed -eq 0){
    $Results.Status="NotAFinding"
}else{
    $Results.Status="Open"
}
$Results.Details=$role


Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73287 [$($Results.Status)]"

#Return results
return $Results
