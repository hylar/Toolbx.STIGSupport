<#
.SYNOPSIS
    This checks for compliancy on V-2380.

    The computer clock synchronization tolerance must be limited to 5 minutes or less.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-2380"

# Initial Variables
$Results = @{
    VulnID   = "V-2380"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$policyName = "MaxClockSkew"
[int]$pass = 7
$raw = $PreCheck.secEdit -match $policyName
if($raw.Length -gt 0){
    [int]$value = $raw -split '= ' | select -Last 1
    if ($value -le $pass) {
        $Results.Status = "NotAFinding"
        $Results.Details = "$policyName is set to $value, indicating clock synchronization tolerance is $value minutes. See comments for details."
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "$policyName is set to $value, instead of being $pass or less! See comments for details."
    }
    $Results.Comments = "Secedit.exe reports: $raw"
}
else{
    $Results.Details = "Value not found in secedit.exe!"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-2380 [$($Results.Status)]"

#Return results
return $Results
