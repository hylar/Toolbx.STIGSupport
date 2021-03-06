<#
.SYNOPSIS
    This checks for compliancy on V-73705.

    The default permissions of global system objects must be strengthened.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73705"

# Initial Variables
$Results = @{
    VulnID   = "V-73705"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty 'HKLM:\\SYSTEM\CurrentControlSet\Control\Session Manager\' -Name ProtectionMode)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.ProtectionMode
    if ($value -eq 1) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Default Access Control List for system objects is operating in protection mode. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Default Access Control List for system objects is not strengthened! See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73705 [$($Results.Status)]"

#Return results
return $Results
