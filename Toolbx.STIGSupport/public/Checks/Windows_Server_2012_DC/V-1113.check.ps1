<#
.SYNOPSIS
    This checks for compliancy on V-1113.

    The built-in guest account must be disabled.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-1113"

# Initial Variables
$Results = @{
    VulnID   = "V-1113"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$raw = $PreCheck.secEdit -match "EnableGuestAccount"
if($raw.Length -gt 0){
    [int]$value = $raw -split '= ' | select -Last 1
    if ($value -eq 0) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Guest account is disabled. See comments for details."
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Guest account is NOT disabled! See comments for details."
    }
    $Results.Comments = "Secedit.exe reports: $raw"
}
else{
    $Results.Details = "Value not found in secedit.exe!"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-1113 [$($Results.Status)]"

#Return results
return $Results
