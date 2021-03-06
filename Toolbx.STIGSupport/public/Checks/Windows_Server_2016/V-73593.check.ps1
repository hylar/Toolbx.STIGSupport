<#
.SYNOPSIS
    This checks for compliancy on V-73593.

    The Windows Remote Management (WinRM) client must not use Basic authentication.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73593"

# Initial Variables
$Results = @{
    VulnID   = "V-73593"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty 'HKLM:\\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\' -Name AllowBasic)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.AllowBasic
    if ($value -eq 0) {
        $Results.Status = "NotAFinding"
        $Results.Details = "WinRM client does not use of Basic authentication. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "WinRM client ALLOWS use of Basic authentication! See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73593 [$($Results.Status)]"

#Return results
return $Results
