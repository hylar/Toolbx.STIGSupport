<#
.SYNOPSIS
    This checks for compliancy on V-1150.

    The built-in Windows password complexity policy must be enabled.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-1150"

# Initial Variables
$Results = @{
    VulnID   = "V-1150"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$raw = $PreCheck.secEdit -match "PasswordComplexity"
if($raw.Length -gt 0){
    [int]$value = $raw -split '= ' | select -Last 1
    if ($value -eq 1) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Password complexity is enforced. See comments for details."
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Password complexity is NOT enforced! See comments for details."
    }
    $Results.Comments = "Secedit.exe reports: $raw"
}
else{
    $Results.Status = "Open"
    $Results.Details = "Value not found in secedit.exe!"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-1150 [$($Results.Status)]"

#Return results
return $Results
