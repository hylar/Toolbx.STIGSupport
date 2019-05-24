<#
.SYNOPSIS
    This checks for compliancy on V-73623.

    Windows Server 2016 built-in administrator account must be renamed.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param(`$PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73623"

# Initial Variables
$Results = @{
    VulnID   = "V-73623"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$raw=$PreCheck.secedit -match "NewAdministratorName"
$value=$raw -split'= ' | select -Last 1
if($value -ne '"Administrator"' -and $value.Length -ge 1){
    $Results.Status="NotAFinding"
}else{
    $Results.Status="Open"
}
$Results.Details="Secedit.exe reports: $raw"

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73623 [$($Results.Status)]"

#Return results
return $Results
