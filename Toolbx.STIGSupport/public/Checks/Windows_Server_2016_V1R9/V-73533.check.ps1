<#
.SYNOPSIS
    This checks for compliancy on V-73533.

    Local users on domain-joined computers must not be enumerated.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73533"

# Initial Variables
$Results = @{
    VulnID   = "V-73533"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key=(Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\ -Name EnumerateLocalUsers)
if(!$key){
    $Results.Details="Registry key not found!"
    $Results.Status="Open"    
}else{
    [int]$value=$key.EnumerateLocalUsers
    if($value -eq 0){
        $Results.Details="$key"
        $Results.Status="NotAFinding"
    }else{
        $Results.Details="$key"
        $Results.Status="Open"
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73533 [$($Results.Status)]"

#Return results
return $Results
