<#
.SYNOPSIS
    This checks for compliancy on V-73543.

    The Application Compatibility Program Inventory must be prevented from collecting data and sending the information to Microsoft.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73543"

# Initial Variables
$Results = @{
    VulnID   = "V-73543"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat\ -Name DisableInventory)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.DisableInventory
    if ($value -eq 1) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Application Compatibility Program Inventory is disabled. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Application Compatibility Program Inventory is NOT disabled! See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73543 [$($Results.Status)]"

#Return results
return $Results
