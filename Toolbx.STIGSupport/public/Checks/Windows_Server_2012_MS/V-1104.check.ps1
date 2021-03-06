<#
.SYNOPSIS
    This checks for compliancy on V-1104.

    The maximum password age must meet requirements.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-1104"

# Initial Variables
$Results = @{
    VulnID   = "V-1104"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$raw = $PreCheck.secEdit -match "MaximumPasswordAge" | Select-Object -First 1
if($raw.Length -gt 0){
    [int]$value = $raw -split '= ' | Select-Object -Last 1
    if ($value -le 60 -and $value -ne 0) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Maximum password age is set to $value. See comments for details."
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Maximum password age is NOT set correctly. See comments for details."
    }
    $Results.Comments = "Secedit.exe reports: $raw"
}
else{
    $Results.Details = "Value not found in secedit.exe!"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-1104 [$($Results.Status)]"

#Return results
return $Results
