<#
.SYNOPSIS
    This checks for compliancy on V-2376.

    Kerberos user logon restrictions must be enforced.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-2376"

# Initial Variables
$Results = @{
    VulnID   = "V-2376"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
if ($PreCheck.hostType -eq "Domain Controller") {
    $policyName = "TicketValidateClient"
    [int]$pass = 1
    $raw = $PreCheck.secEdit -match $policyName
    if($raw.Length -gt 0){
        [int]$value = $raw -split '= ' | select -Last 1
        if ($value -eq $pass) {
            $Results.Status = "NotAFinding"
            $Results.Details = "$policyName is set to $value, indicating every request for a ticket is validated. See comments for details."
        }
        else {
            $Results.Status = "Open"
            $Results.Details = "$policyName is set to $value, instead of $pass! See comments for details."
        }
        $Results.Comments = "Secedit.exe reports: $raw"
    }
    else{
        $Results.Details = "Value not found in secedit.exe!"
    }
}
else {
    $Results.Status = "Not_Applicable"
    $Results.Details = "Check is only valid for Domain Controllers."
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-2376 [$($Results.Status)]"

#Return results
return $Results
