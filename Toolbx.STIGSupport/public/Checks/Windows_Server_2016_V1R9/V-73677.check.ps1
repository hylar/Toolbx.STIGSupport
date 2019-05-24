<#
.SYNOPSIS
    This checks for compliancy on V-73677.

    Remote calls to the Security Account Manager (SAM) must be restricted to Administrators.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param(`$PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73677"

# Initial Variables
$Results = @{
    VulnID   = "V-73677"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key=(Get-ItemProperty 'HKLM:\\SYSTEM\CurrentControlSet\Control\Lsa\' -Name RestrictRemoteSAM)
if(!$key){
    $Results.Details="Registry key not found!"
    $Results.Status="Open"    
}else{
    [string]$value=$key.RestrictRemoteSAM
    if($value -eq "O:BAG:BAD:(A;;RC;;;BA)"){
        $Results.Details="$key"
        $Results.Status="NotAFinding"
    }else{
        $Results.Details="$key"
        $Results.Status="Open"
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73677 [$($Results.Status)]"

#Return results
return $Results
