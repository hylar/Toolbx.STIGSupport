<#
.SYNOPSIS
    This checks for compliancy on V-73367.

    The computer clock synchronization tolerance must be limited to 5 minutes or less.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73367"

# Initial Variables
$Results = @{
    VulnID   = "V-73367"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
if ($PreCheck.HostType -eq "Domain Controller") {
    $raw = $PreCheck.secEdit -match "MaxClockSkew"
    [int]$value = $raw -split '= ' | select -Last 1
    if ($value -le 5) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Clock synchronization tolerance is restricted to 5 minutes or less. Secedit.exe reports: $raw"
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Clock synchronization tolerance is NOT restricted to 5 minutes or less. Secedit.exe reports: $raw"
    }
}
else {
    $Results.Details = "Check is only applicable to Domain Controllers."
    $Results.Status = "Not_Applicable"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73367 [$($Results.Status)]"

#Return results
return $Results
