<#
.SYNOPSIS
    This checks for compliancy on V-73711.

    User Account Control must, at a minimum, prompt administrators for consent on the secure desktop.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param(`$PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73711"

# Initial Variables
$Results = @{
    VulnID   = "V-73711"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key=(Get-ItemProperty 'HKLM:\\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\' -Name ConsentPromptBehaviorAdmin)
if(!$key){
    $Results.Details="Registry key not found!"
    $Results.Status="Open"    
}else{
    [int]$value=$key.ConsentPromptBehaviorAdmin
    if($value -eq 2 -or $value -eq 1){
        $Results.Details="$key"
        $Results.Status="NotAFinding"
    }else{
        $Results.Details="$key"
        $Results.Status="Open"
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73711 [$($Results.Status)]"

#Return results
return $Results
