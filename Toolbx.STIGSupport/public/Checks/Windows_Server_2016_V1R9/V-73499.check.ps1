<#
.SYNOPSIS
    This checks for compliancy on V-73499.

    Internet Protocol version 6 (IPv6) source routing must be configured to the highest protection level to prevent IP source routing.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73499"

# Initial Variables
$Results = @{
    VulnID   = "V-73499"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key=(Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\ -Name DisableIPSourceRouting)
if(!$key){
    $Results.Details="Registry key not found!"
    $Results.Status="Open"    
}else{
    [int]$value=$key.DisableIPSourceRouting
    if($value -eq 2){
        $Results.Details="$key"
        $Results.Status="NotAFinding"
    }else{
        $Results.Details="$key"
        $Results.Status="Open"
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73499 [$($Results.Status)]"

#Return results
return $Results
