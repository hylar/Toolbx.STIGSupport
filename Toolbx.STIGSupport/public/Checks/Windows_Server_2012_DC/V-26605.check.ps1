<#
.SYNOPSIS
    This checks for compliancy on V-26605.

    The Simple TCP/IP Services service must be disabled if installed.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-26605"

# Initial Variables
$Results = @{
    VulnID   = "V-26605"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$serviceName="simptcp"
$startType = "Disabled"
$service=Get-Service -Name $serviceName
if (!$service ) {
    $Results.Status = "NotAFinding"
    $Results.Details = "The '"+$serviceName+"' service is not installed."
}
elseif ($service.StartType -eq $startType) {
    $Results.Status = "NotAFinding"
    $Results.Details = "The startup type of the '"+$service.DisplayName+"' service is "+$service.StartType+". See comments for details."
}
else{
    $Results.Status = "Open"
    $Results.Details = "The startup type of the '"+$service.DisplayName+"' service is "+$service.StartType+"! See comments for details."
}
$Results.Comments = $service | Select-Object DisplayName, Status, StartType | Out-String

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-26605 [$($Results.Status)]"

#Return results
return $Results
