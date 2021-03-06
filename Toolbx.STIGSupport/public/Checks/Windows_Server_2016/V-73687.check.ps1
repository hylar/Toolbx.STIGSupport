<#
.SYNOPSIS
    This checks for compliancy on V-73687.

    Windows Server 2016 must be configured to prevent the storage of the LAN Manager hash of passwords.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73687"

# Initial Variables
$Results = @{
    VulnID   = "V-73687"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty 'HKLM:\\SYSTEM\CurrentControlSet\Control\Lsa\' -Name NoLMHash)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.NoLMHash
    if ($value -eq 1) {
        $Results.Status = "NotAFinding"
        $Results.Details = "LAN Manager does not store password hash. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "LAN Manager ALLOWS storage of password hash! See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73687 [$($Results.Status)]"

#Return results
return $Results
