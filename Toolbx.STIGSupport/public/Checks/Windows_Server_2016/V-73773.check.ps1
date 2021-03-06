<#
.SYNOPSIS
    This checks for compliancy on V-73773.

    The Deny log on through Remote Desktop Services user right on domain controllers must be configured to prevent unauthenticated access.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73773"

# Initial Variables
$Results = @{
    VulnID   = "V-73773"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
if ($PreCheck.HostType -eq "Domain Controller") {
    $right = $PreCheck.userRights -match "SeDenyRemoteInteractiveLogonRight"
    if (!$right) {
        $Results.Details = "Unable to find entry in user rights!"
        $Results.Status = "Open"
    }
    else {
        [string]$value = $right.Accountlist
        if ($value -match "Guests") {
            $Results.Status = "NotAFinding"
            $Results.Details = "Verified Guests group is denied logon. See comments for details."
            $Results.Comments = ($right | Out-String)
        }
        else {
            $Results.Status = "Open"
            $Results.Details = "Guests group NOT denied logon! See comments for details."
            $Results.Comments = ($right | Out-String)
        }
    }
}
else {
    $Results.Details = "Check is only applicable to Domain Controllers."
    $Results.Status = "Not_Applicable"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73773 [$($Results.Status)]"

#Return results
return $Results
