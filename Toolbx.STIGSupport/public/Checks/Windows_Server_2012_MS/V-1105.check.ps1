<#
.SYNOPSIS
    This checks for compliancy on V-1105.

    The minimum password age must meet requirements.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-1105"

# Initial Variables
$Results = @{
    VulnID   = "V-1105"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$raw = $PreCheck.secEdit -match "MinimumPasswordAge"
if($raw.Length -gt 0){
    [int]$value = $raw -split '= ' | select -Last 1
    if ($value -ge 1) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Minimum password age is set to $value. See comments for details."
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Minimum password age is NOT set correctly. See comments for details."
    }
    $Results.Comments = "Secedit.exe reports: $raw"
}
else{
    $Results.Details = "Value not found in secedit.exe!"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-1105 [$($Results.Status)]"

#Return results
return $Results
