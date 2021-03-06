<#
.SYNOPSIS
    This checks for compliancy on V-1107.

    The password history must be configured to 24 passwords remembered.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-1107"

# Initial Variables
$Results = @{
    VulnID   = "V-1107"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$raw = $PreCheck.secEdit -match "PasswordHistorySize"
if($raw.Length -gt 0){
    [int]$value = $raw -split '= ' | select -Last 1
    if ($value -eq 24) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Password history size is set to $value. See comments for details."
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Password history size is NOT set correctly. See comments for details."
    }
    $Results.Comments = "Secedit.exe reports: $raw"
}
else{
    $Results.Details = "Value not found in secedit.exe!"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-1107 [$($Results.Status)]"

#Return results
return $Results
