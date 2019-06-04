<#
.SYNOPSIS
    This checks for compliancy on V-1127.

    Only administrators responsible for the member server must have Administrator rights on the system.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-1127"

# Initial Variables
$Results = @{
    VulnID   = "V-1127"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$admins=Get-LocalGroupMember -Name Administrators

<#
$localAdmin=($precheck.secEdit -match "NewAdministratorName" -split "= " | Select-Object -Last 1) -replace '"',''

$filteredAdmins = $admins | Where-Object {$_.Name -ne "$env:COMPUTERNAME\$localAdmin"}
$filteredAdmins = $filteredAdmins | Where-Object {$_.ObjectClass -ne "Group" -or $_.Name -ne ($PreCheck.domain+"\Domain Member Server Admins")}
#>

$Results.Details = "Please review members of Administrators in comments. CHECK IS WIP"
$Results.Comments = $admins | Format-List | Out-String

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-1127 [$($Results.Status)]"

#Return results
return $Results
