<#
.SYNOPSIS
    This checks for compliancy on V-1098.

    The reset period for the account lockout counter must be configured to 15 minutes or greater on Windows 2012.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-1098"

# Initial Variables
$Results = @{
    VulnID   = "V-1098"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$raw = $PreCheck.secEdit -match "ResetLockoutCount"
if($raw.Length -gt 0){
    [int]$value = $raw -split '= ' | select -Last 1
    if ($value -ge 15) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Time before lockout is reset is set to $value. See comments for details."
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Time before lockout is reset is NOT set correctly. See comments for details."
    }
    $Results.Comments = "Secedit.exe reports: $raw"
}
else{
    $Results.Details = "Value not found in secedit.exe!"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-1098 [$($Results.Status)]"

#Return results
return $Results
