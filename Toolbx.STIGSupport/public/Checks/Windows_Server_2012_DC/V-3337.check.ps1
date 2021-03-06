<#
.SYNOPSIS
    This checks for compliancy on V-3337.

    Anonymous SID/Name translation must not be allowed.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-3337"

# Initial Variables
$Results = @{
    VulnID   = "V-3337"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$raw = $PreCheck.secEdit -match "LSAAnonymousNameLookup"
if($raw.Length -gt 0){
    [int]$value = $raw -split '= ' | select -Last 1
    if ($value -eq 0) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Use of anonymous SID/Name translation is disallowed. See comments for details."
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Use of anonymous SID/Name translation is allowed! See comments for details."
    }
    $Results.Comments = "Secedit.exe reports: $raw"
}
else{
    $Results.Status = "Open"
    $Results.Details = "Value not found in secedit.exe!"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-3337 [$($Results.Status)]"

#Return results
return $Results
