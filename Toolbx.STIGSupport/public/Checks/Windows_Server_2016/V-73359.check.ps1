<#
.SYNOPSIS
    This checks for compliancy on V-73359.

    Kerberos user logon restrictions must be enforced.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73359"

# Initial Variables
$Results = @{
    VulnID   = "V-73359"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
if ($PreCheck.HostType -eq "Domain Controller") {
    $raw = $PreCheck.secEdit -match "TicketValidateClient"
    [int]$value = $raw -split '= ' | select -Last 1
    if ($value -eq 1) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Kerberos login restrictions (ticket validation) is enforced. Secedit.exe reports: $raw"
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Kerberos login restrictions (ticket validation) is NOT enforced. Secedit.exe reports: $raw"
    }
}
else {
    $Results.Details = "Check is only applicable to Domain Controllers."
    $Results.Status = "Not_Applicable"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73359 [$($Results.Status)]"

#Return results
return $Results
