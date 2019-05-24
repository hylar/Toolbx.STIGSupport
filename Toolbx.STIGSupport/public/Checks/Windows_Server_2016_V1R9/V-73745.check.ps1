<#
.SYNOPSIS
    This checks for compliancy on V-73745.

    The Create a pagefile user right must only be assigned to the Administrators group.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param(`$PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73745"

# Initial Variables
$Results = @{
    VulnID   = "V-73745"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$right=$PreCheck.userRights -match "SeCreatePagefilePrivilege"
if(!$right){
    $Results.Details="Unable to find entry in user rights!"
    $Results.Status="Open"   
}else{
    [string]$value=$right.Accountlist
    if(($value -replace "Administrators",'' -replace " ","").Length -eq 0){
        $Results.Details=($right | Out-String)
        $Results.Status="NotAFinding"
    }else{
        $Results.Details=($right | Out-String)
        $Results.Status="Open"
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73745 [$($Results.Status)]"

#Return results
return $Results
