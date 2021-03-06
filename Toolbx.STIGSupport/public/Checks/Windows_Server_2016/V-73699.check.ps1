<#
.SYNOPSIS
    This checks for compliancy on V-73699.

    Users must be required to enter a password to access private keys stored on the computer.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73699"

# Initial Variables
$Results = @{
    VulnID   = "V-73699"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty 'HKLM:\\SOFTWARE\Policies\Microsoft\Cryptography\' -Name ForceKeyProtection)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.ForceKeyProtection
    if ($value -eq 2) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Private keys are required to be password protected. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Private keys do NOT require password protection! See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73699 [$($Results.Status)]"

#Return results
return $Results
