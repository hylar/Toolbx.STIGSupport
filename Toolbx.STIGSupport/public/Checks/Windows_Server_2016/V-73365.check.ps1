<#
.SYNOPSIS
    This checks for compliancy on V-73365.

    The Kerberos policy user ticket renewal maximum lifetime must be limited to seven days or less.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73365"

# Initial Variables
$Results = @{
    VulnID   = "V-73365"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
if ($PreCheck.HostType -eq "Domain Controller") {
    $raw = $PreCheck.secEdit -match "MaxRenewAge"
    [int]$value = $raw -split '= ' | select -Last 1
    if ($value -le 7) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Kerberos user ticket renewal lifetime is restricted to 7 days or less. Secedit.exe reports: $raw"
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Kerberos user ticket renewal lifetime is NOT restricted to 7 days or less. Secedit.exe reports: $raw"
    }
}
else {
    $Results.Details = "Check is only applicable to Domain Controllers."
    $Results.Status = "Not_Applicable"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73365 [$($Results.Status)]"

#Return results
return $Results
