<#
.SYNOPSIS
    This checks for compliancy on V-73695.

    Session security for NTLM SSP-based clients must be configured to require NTLMv2 session security and 128-bit encryption.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73695"

# Initial Variables
$Results = @{
    VulnID   = "V-73695"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty 'HKLM:\\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\' -Name NTLMMinClientSec)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.NTLMMinClientSec
    if ($value -eq 537395200) {
        $Results.Status = "NotAFinding"
        $Results.Details = "NTLM SSP-based clients use NTLMv2 session security and 128-bit encryption. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "NTLM SSP-based clients NOT enforced to use NTLMv2 session security and 128-bit encryption! See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73695 [$($Results.Status)]"

#Return results
return $Results
