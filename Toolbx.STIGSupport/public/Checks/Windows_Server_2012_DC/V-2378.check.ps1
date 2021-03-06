<#
.SYNOPSIS
    This checks for compliancy on V-2378.

    The Kerberos user ticket lifetime must be limited to 10 hours or less.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-2378"

# Initial Variables
$Results = @{
    VulnID   = "V-2378"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$policyName = "MaxTicketAge"
[int]$pass = 600
$raw = $PreCheck.secEdit -match $policyName
if($raw.Length -gt 0){
    [int]$value = $raw -split '= ' | select -Last 1
    if ($value -le $pass) {
        $Results.Status = "NotAFinding"
        $Results.Details = "$policyName is set to $value, indicating Kerberos user ticket max lifetime is $value hours. See comments for details."
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

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-2378 [$($Results.Status)]"

#Return results
return $Results
