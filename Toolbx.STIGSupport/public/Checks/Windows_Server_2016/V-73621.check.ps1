<#
.SYNOPSIS
    This checks for compliancy on V-73621.

    Local accounts with blank passwords must be restricted to prevent access from the network.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73621"

# Initial Variables
$Results = @{
    VulnID   = "V-73621"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty 'HKLM:\\SYSTEM\CurrentControlSet\Control\Lsa\' -Name LimitBlankPasswordUse)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.LimitBlankPasswordUse
    if ($value -eq 1) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Blank password use is restricted. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Blank password use is ALLOWED! See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73621 [$($Results.Status)]"

#Return results
return $Results
