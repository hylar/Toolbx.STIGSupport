<#
.SYNOPSIS
    This checks for compliancy on V-73731.

    The Access this computer from the network user right must only be assigned to the Administrators, Authenticated Users, and Enterprise Domain Controllers groups on domain controllers.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73731"

# Initial Variables
$Results = @{
    VulnID   = "V-73731"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
if ($PreCheck.HostType -eq "Domain Controller") {
    $right = $PreCheck.userRights -match "SeNetworkLogonRight"
    if (!$right) {
        $Results.Details = "Unable to find entry in user rights!"
        $Results.Status = "Open"
    }
    else {
        [string]$value = $right.Accountlist
        if (($value -replace "Administrators", '' -replace "Authenticated Users", '' -replace "Enterprise Domain Controllers" -replace " ", "").Length -eq 0) {
            $Results.Details = ($right | Out-String)
            $Results.Status = "NotAFinding"
        }
        else {
            $Results.Details = ($right | Out-String)
            $Results.Status = "Open"
        }
    }
}
else {
    $Results.Details = "Check is only applicable to Domain Controllers."
    $Results.Status = "Not_Applicable"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73731 [$($Results.Status)]"

#Return results
return $Results
