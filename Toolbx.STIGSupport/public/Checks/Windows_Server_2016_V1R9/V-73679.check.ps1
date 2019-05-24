<#
.SYNOPSIS
    This checks for compliancy on V-73679.

    Services using Local System that use Negotiate when reverting to NTLM authentication must use the computer identity instead of authenticating anonymously.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param(`$PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73679"

# Initial Variables
$Results = @{
    VulnID   = "V-73679"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key=(Get-ItemProperty 'HKLM:\\SYSTEM\CurrentControlSet\Control\LSA\' -Name UseMachineId)
if(!$key){
    $Results.Details="Registry key not found!"
    $Results.Status="Open"    
}else{
    [int]$value=$key.UseMachineId
    if($value -eq 1){
        $Results.Details="$key"
        $Results.Status="NotAFinding"
    }else{
        $Results.Details="$key"
        $Results.Status="Open"
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73679 [$($Results.Status)]"

#Return results
return $Results
