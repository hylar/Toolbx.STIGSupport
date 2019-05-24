<#
.SYNOPSIS
    This checks for compliancy on V-73651.

    Caching of logon credentials must be limited.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73651"

# Initial Variables
$Results = @{
    VulnID   = "V-73651"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key=(Get-ItemProperty 'HKLM:\\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\' -Name CachedLogonsCount)
if(!$key){
    $Results.Details="Registry key not found!"
    $Results.Status="Open"    
}else{
    [int]$value=$key.CachedLogonsCount
    if($value -le 4){
        $Results.Details="$key"
        $Results.Status="NotAFinding"
    }else{
        $Results.Details="$key"
        $Results.Status="Open"
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73651 [$($Results.Status)]"

#Return results
return $Results
