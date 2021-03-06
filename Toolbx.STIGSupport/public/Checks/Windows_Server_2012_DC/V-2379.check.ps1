<#
.SYNOPSIS
    This checks for compliancy on V-2379.

    The Kerberos policy user ticket renewal maximum lifetime must be limited to 7 days or less.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-2379"

# Initial Variables
$Results = @{
    VulnID   = "V-2379"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$policyName = "MaxRenewAge"
[int]$pass = 7
$raw = $PreCheck.secEdit -match $policyName
if($raw.Length -gt 0){
    [int]$value = $raw -split '= ' | select -Last 1
    if ($value -le $pass) {
        $Results.Status = "NotAFinding"
        $Results.Details = "$policyName is set to $value, indicating Kerberos user ticket max renewal lifetime is $value days. See comments for details."
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

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-2379 [$($Results.Status)]"

#Return results
return $Results
