<#
.SYNOPSIS
    This checks for compliancy on V-73497.

    WDigest Authentication must be disabled.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73497"

# Initial Variables
$Results = @{
    VulnID   = "V-73497"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest\ -Name UseLogonCredential)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.UseLogonCredential
    if ($value -eq 0) {
        $Results.Details = $key | Out-String
        $Results.Status = "NotAFinding"
    }
    else {
        $Results.Details = $key | Out-String
        $Results.Status = "Open"
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73497 [$($Results.Status)]"

#Return results
return $Results
