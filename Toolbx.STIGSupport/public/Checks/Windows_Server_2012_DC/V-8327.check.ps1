<#
.SYNOPSIS
    This checks for compliancy on V-8327.

    Windows services that are critical for directory server operation must be configured for automatic startup.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-8327"

# Initial Variables
$Results = @{
    VulnID   = "V-8327"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
[array]$defaultServices = "NTDS","DFSR","Dnscache","DNS","gpsvc","IsmServ","Kdc","Netlogon","W32Time"
[int]$fail = 0
$services = Get-Service $defaultServices -ErrorAction SilentlyContinue
foreach ($start in $services.StartType) {
    if ($start -ne "Automatic") {
        [int]$fail = 1
    }
}
if ($fail -eq 0) {
    $Results.Status = "NotAFinding"
    $Results.Details = "All services required to have a start type of Automatic do. See comments for details."
    $Results.Comments = "-=Services With Incorrect StartType=-"
    $Results.Comments += $services | Select-Object Name, DisplayName, StartType | Where-Object {$_.StartType -ne "Automatic"} | Format-List | Out-String
}
else {
    $Results.Status = "Open"
    $Results.Details = "Some services required to have a start type of Automatic do NOT; Please review! See comments for details."
}
$Results.Comments += "-=All Relevant Services=-"
$Results.Comments += $services | Select-Object Name, DisplayName, StartType | Format-List | Out-String

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-8327 [$($Results.Status)]"

#Return results
return $Results
