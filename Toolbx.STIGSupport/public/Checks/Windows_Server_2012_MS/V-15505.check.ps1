<#
.SYNOPSIS
    This checks for compliancy on V-15505.

    The HBSS McAfee Agent must be installed.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-15505"

# Initial Variables
$Results = @{
    VulnID   = "V-15505"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$service=Get-Service | Where-Object {$_.DisplayName -eq 'McAfee Agent Service' -or $_.DisplayName -eq 'McAfee Framework Service'}
if ($service.Status -eq 'Running') {
    $Results.Status = "NotAFinding"
    $Results.Details = "Found "+$service.DisplayName+" and verified status is "+$service.Status+". See comments for details."
    $Results.Comments = $service | Format-List | Out-String
}
else {
    $Results.Status = "Open"
    $Results.Details = "Could not find McAfee Agent service, please investigate!"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-15505 [$($Results.Status)]"

#Return results
return $Results
