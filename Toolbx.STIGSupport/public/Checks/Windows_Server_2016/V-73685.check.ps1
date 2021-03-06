<#
.SYNOPSIS
    This checks for compliancy on V-73685.

    Kerberos encryption types must be configured to prevent the use of DES and RC4 encryption suites.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73685"

# Initial Variables
$Results = @{
    VulnID   = "V-73685"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty 'HKLM:\\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\' -Name SupportedEncryptionTypes)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.SupportedEncryptionTypes
    if ($value -eq 2147483640) {
        $Results.Status = "NotAFinding"
        $Results.Details = "DES and RC4 encryption is not permitted. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Supported encryption is non-standard! See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73685 [$($Results.Status)]"

#Return results
return $Results
