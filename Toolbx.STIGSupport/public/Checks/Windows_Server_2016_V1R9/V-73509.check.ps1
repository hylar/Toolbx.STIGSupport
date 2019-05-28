<#
.SYNOPSIS
    This checks for compliancy on V-73509.

    Hardened UNC paths must be defined to require mutual authentication and integrity for at least the \\*\SYSVOL and \\*\NETLOGON shares.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73509"

# Initial Variables
$Results = @{
    VulnID   = "V-73509"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\ -Name \\*\NETLOGON)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [string]$value = $key | select \\*\NETLOGON
    if ($value -match "RequireMutualAuthentication=1, RequireIntegrity=1") {
        $Results.Details = $key | Out-String
        $Results.Status = "NotAFinding"
    }
    else {
        $Results.Details = $key | Out-String
        $Results.Status = "Open"
    }
}

$key2 = (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\ -Name \\*\SYSVOL)
if (!$key) {
    $Results.Details += "`r`nRegistry key not found!"
    $Results.Status = "Open"
}
else {
    [string]$value = $key2 | select \\*\SYSVOL
    if ($value -match "RequireMutualAuthentication=1, RequireIntegrity=1" -and $Results.Status -eq "NotAFinding") {
        $Results.Details += "`r`n$key2"
        $Results.Status = "NotAFinding"
    }
    else {
        $Results.Details += "`r`n$key2"
        $Results.Status = "Open"
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73509 [$($Results.Status)]"

#Return results
return $Results
