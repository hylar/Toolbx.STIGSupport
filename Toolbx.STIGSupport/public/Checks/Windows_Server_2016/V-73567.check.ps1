<#
.SYNOPSIS
    This checks for compliancy on V-73567.

    Passwords must not be saved in the Remote Desktop Client.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73567"

# Initial Variables
$Results = @{
    VulnID   = "V-73567"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' -Name DisablePasswordSaving)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.DisablePasswordSaving
    if ($value -eq 1) {
        $Results.Status = "NotAFinding"
        $Results.Details = "RDC configured to prevent saving of passwords. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "RDC configured to ALLOW saving of passwords. See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73567 [$($Results.Status)]"

#Return results
return $Results
