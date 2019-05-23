<#
.SYNOPSIS
    This checks for compliancy on V-73579.

    Basic authentication for RSS feeds over HTTP must not be used.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param(`$PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73579"

# Initial Variables
$Results = @{
    VulnID   = "V-73579"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key=(Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds\' -Name AllowBasicAuthInClear)
if(!$key){
    $Results.Details="Registry key was not found."
    $Results.Status="NotAFinding"    
}else{
    [int]$value=$key.AllowBasicAuthInClear
    if($value -eq 0){
        $Results.Details="$key"
        $Results.Status="NotAFinding"
    }else{
        $Results.Details="$key"
        $Results.Status="Open"
    }    
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73579 [$($Results.Status)]"

#Return results
return $Results
