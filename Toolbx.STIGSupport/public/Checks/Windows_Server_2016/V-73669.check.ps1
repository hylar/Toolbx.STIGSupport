<#
.SYNOPSIS
    This checks for compliancy on V-73669.

    Anonymous enumeration of shares must not be allowed.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73669"

# Initial Variables
$Results = @{
    VulnID   = "V-73669"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty 'HKLM:\\SYSTEM\CurrentControlSet\Control\Lsa\' -Name RestrictAnonymous)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.RestrictAnonymous
    if ($value -eq 1) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Anonymous enumeration of shares is restricted. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Anonymous enumeration of shares is NOT restricted! See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73669 [$($Results.Status)]"

#Return results
return $Results
