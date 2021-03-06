<#
.SYNOPSIS
    This checks for compliancy on V-73551.

    Windows Telemetry must be configured to Security or Basic.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73551"

# Initial Variables
$Results = @{
    VulnID   = "V-73551"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection\ -Name AllowTelemetry)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.AllowTelemetry
    if ($value -eq 0) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Windows telemetry is set to 'Security.' See comments for details."
        $Results.Comments = $key | Out-String
    }
    elseif ($value -eq 1) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Windows telemetry is set to 'Basic.' See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Windows telemetry is not set to a secure value! See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73551 [$($Results.Status)]"

#Return results
return $Results
