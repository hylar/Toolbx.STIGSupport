<#
.SYNOPSIS
    This checks for compliancy on V-1099.

    Windows 2012 account lockout duration must be configured to 15 minutes or greater.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-1099"

# Initial Variables
$Results = @{
    VulnID   = "V-1099"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$raw = $PreCheck.secEdit -match "LockoutDuration"
if($raw.Length -gt 0){
    [int]$value = $raw -split '= ' | select -Last 1
    if ($value -ge 15) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Time to remain locked after failed logons is set to $value. See comments for details."

    }
    #-1 in secEdit is equivalent to 0 in gpedit
    elseif($value -eq 0 -or $value -eq -1){
        $Results.Status = "NotAFinding"
        $Results.Details = "Accounts are set to remain locked after failed logons. See comments for details."
        $Results.Comments = "Secedit.exe reports: $raw (-1 in secedit.exe is equivalent to 0 in gpedit.msc)"
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Time to remain locked after failed logons is NOT set correctly. See comments for details."
        $Results.Comments = "Secedit.exe reports: $raw"
    }
}
else{
    $Results.Details = "Value not found in secedit.exe!"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-1099 [$($Results.Status)]"

#Return results
return $Results
