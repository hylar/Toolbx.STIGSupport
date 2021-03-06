<#
.SYNOPSIS
    This checks for compliancy on V-26490.

    The Impersonate a client after authentication user right must only be assigned to Administrators, Service, Local Service, and Network Service.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-26490"

# Initial Variables
$Results = @{
    VulnID   = "V-26490"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$right = $PreCheck.userRights -match "SeImpersonatePrivilege"
if (!$right) {
    $Results.Details = "Unable to find entry in user rights!"
    $Results.Status = "Open"
}
else {
    [string]$value = $right.Accountlist
    if (($value -replace "Administrators", '' -replace "Local Service", '' -replace "Network Service", '' -replace "Service", '' -replace " ", "").Length -eq 0) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Verified impersonate a client after authentication right is only given to Administrators, Service, Network Service, and Local Service. See comments for details."
        $Results.Comments = ($right | Out-String)
    }
    $Results.Comments = ($right | Out-String)
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Impersonate a client after authentication right contains more users/groups than Administrators, Service, Network Service, and Local Service; Please review! See comments for details."
        $Results.Comments = ($right | Out-String)
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-26490 [$($Results.Status)]"

#Return results
return $Results
