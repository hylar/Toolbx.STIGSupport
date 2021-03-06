<#
.SYNOPSIS
    This checks for compliancy on V-1115.

    The built-in administrator account must be renamed.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-1115"

# Initial Variables
$Results = @{
    VulnID   = "V-1115"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$raw = $PreCheck.secEdit -match "NewAdministratorName"
if($raw.Length -gt 0){
    [string]$value = $raw -split '= ' | select -Last 1
    if ($value -ne "Administrator") {
        $Results.Status = "NotAFinding"
        $Results.Details = "Adminsitrator account has been renamed to $value. See comments for details."
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Adminsitrator account has NOT been renamed! See comments for details."
    }
    $Results.Comments = "Secedit.exe reports: $raw"
}
else{
    $Results.Details = "Value not found in secedit.exe!"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-1115 [$($Results.Status)]"

#Return results
return $Results
