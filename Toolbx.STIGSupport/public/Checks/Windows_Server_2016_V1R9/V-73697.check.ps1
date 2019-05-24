<#
.SYNOPSIS
    This checks for compliancy on V-73697.

    Session security for NTLM SSP-based servers must be configured to require NTLMv2 session security and 128-bit encryption.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param(`$PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73697"

# Initial Variables
$Results = @{
    VulnID   = "V-73697"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key=(Get-ItemProperty 'HKLM:\\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\' -Name NTLMMinServerSec)
if(!$key){
    $Results.Details="Registry key not found!"
    $Results.Status="Open"    
}else{
    [int]$value=$key.NTLMMinServerSec
    if($value -eq 537395200){
        $Results.Details="$key"
        $Results.Status="NotAFinding"
    }else{
        $Results.Details="$key"
        $Results.Status="Open"
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73697 [$($Results.Status)]"

#Return results
return $Results
