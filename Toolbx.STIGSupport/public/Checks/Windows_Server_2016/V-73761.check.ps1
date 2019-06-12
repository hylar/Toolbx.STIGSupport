<#
.SYNOPSIS
    This checks for compliancy on V-73761.

    The Deny log on as a batch job user right on domain controllers must be configured to prevent unauthenticated access.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73761"

# Initial Variables
$Results = @{
    VulnID   = "V-73761"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
if ($PreCheck.HostType -eq "Domain Controller") {
    $right = $PreCheck.userRights -match "SeDenyBatchLogonRight"
    if (!$right) {
        $Results.Details = "Unable to find entry in user rights!"
        $Results.Status = "Open"
    }
    else {
        [string]$value = $right.Accountlist
        if ($value -match "Guests") {
            $Results.Status = "NotAFinding"
            $Results.Details = "Verified Guests are denied logon as a batch job. See comments for details."
            $Results.Comments = ($right | Out-String)
        }
        else {
            $Results.Status = "Open"
            $Results.Details = "Unable to verify Guests are denied logon as a batch job, please review! See comments for details."
            $Results.Comments = ($right | Out-String)
        }
    }
}
else {
    $Results.Details = "Check is only applicable to Domain Controllers."
    $Results.Status = "Not_Applicable"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73761 [$($Results.Status)]"

#Return results
return $Results
