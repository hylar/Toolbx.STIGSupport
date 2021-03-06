<#
.SYNOPSIS
    This checks for compliancy on V-26602.

    The Microsoft FTP service must not be installed unless required.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-26602"

# Initial Variables
$Results = @{
    VulnID   = "V-26602"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$role=Get-WindowsFeature Web-FTP-Server
$serviceName="FTPSVC"
$service=Get-Service -Name $serviceName
if (!$service -and $role.Installed -eq $false) {
    $Results.Status = "NotAFinding"
    $Results.Details = "The '"+$serviceName+"' service is not installed."
}
else{
    $Results.Status = "Open"
    $Results.Details = "The startup type of the '"+$service.DisplayName+"' service is "+$service.StartType+"! See comments for details."
}
$Results.Comments = $service | Select-Object DisplayName, Status, StartType | Out-String

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-26602 [$($Results.Status)]"

#Return results
return $Results
