<#
.SYNOPSIS
    This checks for compliancy on V-6836.

    Passwords must, at a minimum, be 14 characters.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-6836"

# Initial Variables
$Results = @{
    VulnID   = "V-6836"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$raw = $PreCheck.secEdit -match "MinimumPasswordLength"
if($raw.Length -gt 0){
    [int]$value = $raw -split '= ' | select -Last 1
    if ($value -ge 14) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Password minimum length is $value. See comments for details."
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Password minimum length is $value, when it should be at least 14! See comments for details."
    }
    $Results.Comments = "Secedit.exe reports: $raw"
}
else{
    $Results.Status = "Open"
    $Results.Details = "Value not found in secedit.exe!"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-6836 [$($Results.Status)]"

#Return results
return $Results
