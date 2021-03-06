<#
.SYNOPSIS
    This checks for compliancy on V-73777.

    The Enable computer and user accounts to be trusted for delegation user right must only be assigned to the Administrators group on domain controllers.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73777"

# Initial Variables
$Results = @{
    VulnID   = "V-73777"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
if ($PreCheck.HostType -eq "Domain Controller") {
    $right = $PreCheck.userRights -match "SeEnableDelegationPrivilege"
    if (!$right) {
        $Results.Details = "Unable to find entry in user rights!"
        $Results.Status = "Open"
    }
    else {
        [string]$value = $right.Accountlist
        if (($value -replace "Administrators", '' -replace " ", "").Length -eq 0) {
            $Results.Status = "NotAFinding"
            $Results.Details = "Accounts are trusted for delegation includes only Administrators. See comments for details."
            $Results.Comments = ($right | Out-String)
        }
        else {
            $Results.Status = "Open"
            $Results.Details = "Additional accounts have the trusted for delegation right! See comments for details."
            $Results.Comments = ($right | Out-String)
        }
    }
}
else {
    $Results.Details = "Check is only applicable to Domain Controllers."
    $Results.Status = "Not_Applicable"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73777 [$($Results.Status)]"

#Return results
return $Results
