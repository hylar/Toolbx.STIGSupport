<#
.SYNOPSIS
    This checks for compliancy on V-73691.

    The LAN Manager authentication level must be set to send NTLMv2 response only and to refuse LM and NTLM.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73691"

# Initial Variables
$Results = @{
    VulnID   = "V-73691"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty 'HKLM:\\SYSTEM\CurrentControlSet\Control\Lsa\' -Name LmCompatibilityLevel)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.LmCompatibilityLevel
    if ($value -eq 5) {
        $Results.Status = "NotAFinding"
        $Results.Details = "LAN Manager authentication only uses NTLMv2. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "LAN Manager authentication allows non-NTLMv2! See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73691 [$($Results.Status)]"

#Return results
return $Results
