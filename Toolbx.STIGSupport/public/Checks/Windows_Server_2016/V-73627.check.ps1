<#
.SYNOPSIS
    This checks for compliancy on V-73627.

    Audit policy using subcategories must be enabled.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73627"

# Initial Variables
$Results = @{
    VulnID   = "V-73627"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty 'HKLM:\\SYSTEM\CurrentControlSet\Control\Lsa\' -Name SCENoApplyLegacyAuditPolicy)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.SCENoApplyLegacyAuditPolicy
    if ($value -eq 1) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Audit policy set to have subcategories override categories. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Audit policy does NOT enforce subcategories overriding categories! See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73627 [$($Results.Status)]"

#Return results
return $Results
