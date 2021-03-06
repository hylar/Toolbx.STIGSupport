<#
.SYNOPSIS
    This checks for compliancy on V-73683.

    PKU2U authentication using online identities must be prevented.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73683"

# Initial Variables
$Results = @{
    VulnID   = "V-73683"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty 'HKLM:\\SYSTEM\CurrentControlSet\Control\LSA\pku2u\' -Name AllowOnlineID)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.AllowOnlineID
    if ($value -eq 0) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Authentication using online ID not allowed. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Authentication using online ID is ALLOWED! See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73683 [$($Results.Status)]"

#Return results
return $Results
