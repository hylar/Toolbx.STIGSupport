<#
.SYNOPSIS
    This checks for compliancy on V-73361.

    The Kerberos service ticket maximum lifetime must be limited to 600 minutes or less.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73361"

# Initial Variables
$Results = @{
    VulnID   = "V-73361"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
if ($PreCheck.HostType -eq "Domain Controller") {
    $raw = $PreCheck.secEdit -match "MaxServiceAge"
    [int]$value = $raw -split '= ' | select -Last 1
    if ($value -ne 0 -and $value -le 600) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Kerberos service ticket age is restricted to 600 minutes or less. Secedit.exe reports: $raw"
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Kerberos service ticket age is NOT restricted to 600 minutes or less. Secedit.exe reports: $raw"
    }
}
else {
    $Results.Details = "Check is only applicable to Domain Controllers."
    $Results.Status = "Not_Applicable"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73361 [$($Results.Status)]"

#Return results
return $Results
