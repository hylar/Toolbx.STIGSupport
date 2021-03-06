<#
.SYNOPSIS
    This checks for compliancy on V-1097.

    The number of allowed bad logon attempts must meet minimum requirements.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-1097"

# Initial Variables
$Results = @{
    VulnID   = "V-1097"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$raw = $PreCheck.secEdit -match "LockoutBadCount"
if($raw.Length -gt 0){
    [int]$value = $raw -split '= ' | select -Last 1
    if ($value -eq 1 -or $value -eq 2 -or $value -eq 3) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Number of login attempts before lockout is set to $value. See comments for details."
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Number of login attempts before lockout is NOT set correctly. See comments for details."
    }
    $Results.Comments = "Secedit.exe reports: $raw"
}
else{
    $Results.Details = "Value not found in secedit.exe!"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-1097 [$($Results.Status)]"

#Return results
return $Results
