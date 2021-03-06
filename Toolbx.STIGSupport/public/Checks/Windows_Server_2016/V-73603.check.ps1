<#
.SYNOPSIS
    This checks for compliancy on V-73603.

    The Windows Remote Management (WinRM) service must not store RunAs credentials.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73603"

# Initial Variables
$Results = @{
    VulnID   = "V-73603"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty 'HKLM:\\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\' -Name DisableRunAs)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.DisableRunAs
    if ($value -eq 1) {
        $Results.Status = "NotAFinding"
        $Results.Details = "WinRM service does not store RunAs credentials. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "WinRM service ALLOWS storage RunAs credentials. See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73603 [$($Results.Status)]"

#Return results
return $Results
