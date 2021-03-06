<#
.SYNOPSIS
    This checks for compliancy on V-73529.

    Printing over HTTP must be prevented.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73529"

# Initial Variables
$Results = @{
    VulnID   = "V-73529"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\' -Name DisableHTTPPrinting)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.DisableHTTPPrinting
    if ($value -eq 1) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Printing over HTTP is disabled. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Printing over HTTP is NOT disabled. See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73529 [$($Results.Status)]"

#Return results
return $Results
