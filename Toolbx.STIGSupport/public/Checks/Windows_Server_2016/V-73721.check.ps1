<#
.SYNOPSIS
    This checks for compliancy on V-73721.

    User Account Control must virtualize file and registry write failures to per-user locations.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73721"

# Initial Variables
$Results = @{
    VulnID   = "V-73721"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty 'HKLM:\\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\' -Name EnableVirtualization)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.EnableVirtualization
    if ($value -eq 1) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Virtualization of file and registry write failures to per-user locations is enabled. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Virtualization of file and registry write failures to per-user locations is NOT enabled! See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73721 [$($Results.Status)]"

#Return results
return $Results
