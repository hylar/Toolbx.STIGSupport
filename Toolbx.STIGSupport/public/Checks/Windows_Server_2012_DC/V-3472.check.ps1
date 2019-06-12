<#
.SYNOPSIS
    This checks for compliancy on V-3472.

    The time service must synchronize with an appropriate DoD time source.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-3472"

# Initial Variables
$Results = @{
    VulnID   = "V-3472"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$time = W32tm /query /configuration
$timeType = $time -match "Type"
if ($timeType -like "Type: NT5DS*") {
    $Results.Status = "NotAFinding"
    $Results.Details = "NTP settings are NT5DS, indicating system synchronizes with domain controller. See comments for details."
}
elseif ($timeType -like "Type: NTP*") {
        $Results.Details = "NTP settings are NTP and require verification! See comments for details."
}
else {
    $Results.Status = "Open"
    $Results.Details = "Could not find NT5DS or NTP types in time configuration! See comments for details."
}
$Results.Comments = $time | Out-String


Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-3472 [$($Results.Status)]"

#Return results
return $Results
