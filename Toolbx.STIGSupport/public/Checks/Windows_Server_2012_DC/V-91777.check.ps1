<#
.SYNOPSIS
    This checks for compliancy on V-91777.

    The password for the krbtgt account on a domain must be reset at least every 180 days.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig. 
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-91777"

# Initial Variables
$Results = @{
    VulnID   = "V-91777"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
if ($PreCheck.hostType -eq "Domain Controller") {
    [datetime]$lastSet = (Get-ADUser krbtgt -Property PasswordLastSet).PasswordLastSet
    [datetime]$date = Get-Date
    if ($lastSet -ge $date.AddDays(-180)) {
        $Results.Status = "NotAFinding"
        $Results.Details = "'krbtgt' password was last set on $lastSet; This is within 180 days."
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "'krbtgt' password was last set on $lastSet; This is over 180 days!"
    }
}
else {
    $Results.Status = "Not_Applicable"
    $Results.Details = "Check only applies to domain controllers."
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-91777 [$($Results.Status)]"

#Return results
return $Results
