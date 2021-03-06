<#
.SYNOPSIS
    This checks for compliancy on V-73765.

    The Deny log on as a service user right must be configured to include no accounts or groups (blank) on domain controllers.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73765"

# Initial Variables
$Results = @{
    VulnID   = "V-73765"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
if ($PreCheck.HostType -eq "Domain Controller") {
    $right = $PreCheck.userRights -match "SeDenyServiceLogonRight"
    if (!$right) {
        $Results.Details = "Unable to find entry in user rights!"
        $Results.Status = "Open"
    }
    else {
        [string]$value = $right.Accountlist
        if (($value).Length -eq 0) {
            $Results.Status = "NotAFinding"
            $Results.Details = "Verified no accounts or groups are denied logon as a service. See comments for details."
            $Results.Comments = ($right | Out-String)
        }
        else {
            $Results.Status = "Open"
            $Results.Details = "Found some accounts that are denied logon as a service, please review! See comments for details."
            $Results.Comments = ($right | Out-String)
        }
    }
}
else {
    $Results.Details = "Check is only applicable to Domain Controllers."
    $Results.Status = "Not_Applicable"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73765 [$($Results.Status)]"

#Return results
return $Results
