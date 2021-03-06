<#
.SYNOPSIS
    This checks for compliancy on V-3380.

    The system must be configured to force users to log off when their allowed logon hours expire.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-3380"

# Initial Variables
$Results = @{
    VulnID   = "V-3380"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$raw = $PreCheck.secEdit -match "ForceLogoffWhenHourExpire"
if($raw.Length -gt 0){
    [int]$value = $raw -split '= ' | select -Last 1
    if ($value -eq 1) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Logoff is forced when logon hours expire. See comments for details."
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Logoff when logon hours expire is NOT forced! See comments for details."
    }
    $Results.Comments = "Secedit.exe reports: $raw"
}
else{
    $Results.Status = "Open"
    $Results.Details = "Value not found in secedit.exe!"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-3380 [$($Results.Status)]"

#Return results
return $Results
