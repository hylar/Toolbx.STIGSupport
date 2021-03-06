<#
.SYNOPSIS
    This checks for compliancy on V-73693.

    Windows Server 2016 must be configured to at least negotiate signing for LDAP client signing.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73693"

# Initial Variables
$Results = @{
    VulnID   = "V-73693"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty 'HKLM:\\SYSTEM\CurrentControlSet\Services\LDAP\' -Name LDAPClientIntegrity)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.LDAPClientIntegrity
    if ($value -eq 1) {
        $Results.Status = "NotAFinding"
        $Results.Details = "System negotiates for LDAP client signing. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "System does NOT negotiate for LDAP client signing! See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73693 [$($Results.Status)]"

#Return results
return $Results
