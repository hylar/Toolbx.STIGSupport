<#
.SYNOPSIS
    This checks for compliancy on V-73749.

    The Create global objects user right must only be assigned to Administrators

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73749"

# Initial Variables
$Results = @{
    VulnID   = "V-73749"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$right = $PreCheck.userRights -match "SeCreateGlobalPrivilege"
if (!$right) {
    $Results.Details = "Unable to find entry in user rights!"
    $Results.Status = "Open"
}
else {
    [string]$value = $right.Accountlist
    if (($value -replace "Administrators", '' -replace "Local Service", '' -replace "Network Service", '' -replace "Service", '' -replace " ", "").Length -eq 0) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Verified create global object right contains only Administrators, Service, Local Service, and Network Service. See comments for details."
        $Results.Comments = ($right | Out-String)
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Create global object right contains more users/groups than  Administrators, Service, Local Service, and Network Service; Please review! See comments for details."
        $Results.Comments = ($right | Out-String)
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73749 [$($Results.Status)]"

#Return results
return $Results
