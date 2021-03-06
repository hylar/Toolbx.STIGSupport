<#
.SYNOPSIS
    This checks for compliancy on V-73505.

    Windows Server 2016 must be configured to ignore NetBIOS name release requests except from WINS servers.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73505"

# Initial Variables
$Results = @{
    VulnID   = "V-73505"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters\ -Name NoNameReleaseOnDemand)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.NoNameReleaseOnDemand
    if ($value -eq 1) {
        $Results.Status = "NotAFinding"
        $Results.Details = "System ignores name release on demand. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Name releases on demand allowed! See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73505 [$($Results.Status)]"

#Return results
return $Results
