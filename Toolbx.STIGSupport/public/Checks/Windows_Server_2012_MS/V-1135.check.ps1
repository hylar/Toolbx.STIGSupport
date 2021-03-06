<#
.SYNOPSIS
    This checks for compliancy on V-1135.

    Nonadministrative user accounts or groups must only have print permissions on printer shares.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-1135"

# Initial Variables
$Results = @{
    VulnID   = "V-1135"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$printers=Get-Printer -Full | Select-Object Name,Shared
$sharingStatus=$printers.Shared
if ($sharingStatus -match "True"){
    #CHECK IS WIP
    $Results.Details = "This machine contains shared printers, please review rights!"
    $Results.Comments = $printers | Format-List | Out-String
}
else {
    $Results.Status = "NotAFinding"
    $Results.Details = "No printers are shared on this machine."
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-1135 [$($Results.Status)]"

#Return results
return $Results
