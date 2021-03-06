<#
.SYNOPSIS
    This checks for compliancy on V-73487.

    Administrator accounts must not be enumerated during elevation.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73487"

# Initial Variables
$Results = @{
    VulnID   = "V-73487"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\ -Name EnumerateAdministrators)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}else {
    [int]$value = $key.EnumerateAdministrators
    if ($value -eq 0) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Enumerate administrators is disabled. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Enumerate administrators is NOT disabled. See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73487 [$($Results.Status)]"

#Return results
return $Results
