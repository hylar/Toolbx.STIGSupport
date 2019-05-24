<#
.SYNOPSIS
    This checks for compliancy on V-73807.

    The Smart Card removal option must be configured to Force Logoff or Lock Workstation.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param(`$PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73807"

# Initial Variables
$Results = @{
    VulnID   = "V-73807"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key=(Get-ItemProperty 'HKLM:\\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\' -Name scremoveoption)
if(!$key){
    $Results.Details="Registry key not found!"
    $Results.Status="Open"    
}else{
    [int]$value=$key.scremoveoption
    if($value -eq 1 -or $value -eq 2){
        $Results.Details="$key"
        $Results.Status="NotAFinding"
    }else{
        $Results.Details="$key"
        $Results.Status="Open"
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73807 [$($Results.Status)]"

#Return results
return $Results
