<#
.SYNOPSIS
    This checks for compliancy on V-73569.

    Local drives must be prevented from sharing with Remote Desktop Session Hosts.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73569"

# Initial Variables
$Results = @{
    VulnID   = "V-73569"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' -Name fDisableCdm)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.fDisableCdm
    if ($value -eq 1) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Local drives are prevented from sharing with Remote Desktop Session Hosts. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Local drives ALLOW sharing with Remote Desktop Session Hosts. See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73569 [$($Results.Status)]"

#Return results
return $Results
