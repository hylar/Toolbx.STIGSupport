<#
.SYNOPSIS
    This checks for compliancy on V-73625.

    Windows Server 2016 built-in guest account must be renamed.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param(`$PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73625"

# Initial Variables
$Results = @{
    VulnID   = "V-73625"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$raw=$PreCheck.secedit -match "NewGuestName"
$value=$raw -split'= ' | select -Last 1
if($value -ne '"Guest"' -and $value.Length -ge 1){
    $Results.Status="NotAFinding"
}else{
    $Results.Status="Open"
}
$Results.Details="Secedit.exe reports: $raw"

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73625 [$($Results.Status)]"

#Return results
return $Results
