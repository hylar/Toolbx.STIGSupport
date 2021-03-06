<#
.SYNOPSIS
    This checks for compliancy on V-40206.

    The Smart Card Removal Policy service must be configured to automatic.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-40206"

# Initial Variables
$Results = @{
    VulnID   = "V-40206"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$serviceName = "SCPolicySvc"
$startType = "Automatic"
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

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-40206 [$($Results.Status)]"

#Return results
return $Results
