<#
.SYNOPSIS
    This checks for compliancy on V-73661.

    The setting Microsoft network server: Digitally sign communications (always) must be configured to Enabled.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param(`$PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73661"

# Initial Variables
$Results = @{
    VulnID   = "V-73661"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key=(Get-ItemProperty 'HKLM:\\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\' -Name RequireSecuritySignature)
if(!$key){
    $Results.Details="Registry key not found!"
    $Results.Status="Open"    
}else{
    [int]$value=$key.RequireSecuritySignature
    if($value -eq 1){
        $Results.Details="$key"
        $Results.Status="NotAFinding"
    }else{
        $Results.Details="$key"
        $Results.Status="Open"
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73661 [$($Results.Status)]"

#Return results
return $Results
