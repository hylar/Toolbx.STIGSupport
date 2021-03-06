<#
.SYNOPSIS
    This checks for compliancy on V-73667.

    Anonymous enumeration of Security Account Manager (SAM) accounts must not be allowed.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73667"

# Initial Variables
$Results = @{
    VulnID   = "V-73667"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty 'HKLM:\\SYSTEM\CurrentControlSet\Control\Lsa\' -Name RestrictAnonymousSAM)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.RestrictAnonymousSAM
    if ($value -eq 1) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Anonymous enumeration of SAM accounts is restricted. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Anonymous enumeration of SAM accounts is NOT restricted! See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73667 [$($Results.Status)]"

#Return results
return $Results
