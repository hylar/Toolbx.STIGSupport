<#
.SYNOPSIS
    This checks for compliancy on V-73779.

    The Enable computer and user accounts to be trusted for delegation user right must not be assigned to any groups or accounts on member servers.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73779"

# Initial Variables
$Results = @{
    VulnID   = "V-73779"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
if ($PreCheck.HostType -ne "Domain Controller") {
    $right = $PreCheck.userRights -match "SeEnableDelegationPrivilege"
    if (!$right) {
        $Results.Details = "Unable to find entry in user rights!"
        $Results.Status = "Open"
    }
    else {
        [string]$value = $right.Accountlist
        if (($value).Length -eq 0) {
            $Results.Status = "NotAFinding"
            $Results.Details = "No accounts are trusted for delegation. See comments for details."
            $Results.Comments = ($right | Out-String)
        }
        else {
            $Results.Status = "Open"
            $Results.Details = "Some accounts have the trusted for delegation right! See comments for details."
            $Results.Comments = ($right | Out-String)
        }
    }
}
else {
    $Results.Details = "Check is NOT applicable to Domain Controllers."
    $Results.Status = "Not_Applicable"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73779 [$($Results.Status)]"

#Return results
return $Results
