<#
.SYNOPSIS
    This checks for compliancy on V-73629.

    Domain controllers must require LDAP access signing.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73629"

# Initial Variables
$Results = @{
    VulnID   = "V-73629"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
if ($PreCheck.HostType -eq "Domain Controller") {
    $keyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\"
    $valueName = "LDAPServerIntegrity"
    $key = (Get-ItemProperty $keyPath -Name $valueName -ErrorAction SilentlyContinue)
    if (!$key) {
        $Results.Details = "Registry value at $keyPath with name $valueName was not found!"
        $Results.Status = "Open"
    }
    else {
        [int]$value = $key.valueName
        if ($value -eq 2) {
            $Results.Status = "NotAFinding"
            $Results.Details = "LDAP access signing is required. See comments for details."
            $Results.Comments = $key | Out-String
        }
        else {
            $Results.Status = "Open"
            $Results.Details = "LDAP access signing is NOT required! See comments for details."
            $Results.Comments = $key | Out-String
        }
    }
}
else {
    $Results.Details = "Check is only applicable to Domain Controllers."
    $Results.Status = "Not_Applicable"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73629 [$($Results.Status)]"

#Return results
return $Results
