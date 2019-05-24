<#
.SYNOPSIS
    This checks for compliancy on V-73561.

    Explorer Data Execution Prevention must be enabled.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73561"

# Initial Variables
$Results = @{
    VulnID   = "V-73561"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key=(Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\ -Name NoDataExecutionPrevention)
if(!$key){
    $Results.Details="Registry key was not found."
    $Results.Status="NotAFinding"
}else{
    [int]$value=$key.NoDataExecutionPrevention
    if($value -eq 0){
        $Results.Details="$key"
        $Results.Status="NotAFinding"
    }else{
        $Results.Details="$key"
        $Results.Status="Open"
    }    
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73561 [$($Results.Status)]"

#Return results
return $Results
