<#
.SYNOPSIS
    This checks for compliancy on V-73561.

    Explorer Data Execution Prevention must be enabled.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73561"

# Initial Variables
$Results = @{
    VulnID   = "V-73561"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\ -Name NoDataExecutionPrevention)
if (!$key) {
    $Results.Details = "Registry key was not found."
    $Results.Status = "NotAFinding"
}
else {
    [int]$value = $key.NoDataExecutionPrevention
    if ($value -eq 0) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Explorer Data Execution Prevention is enabled. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Explorer Data Execution Prevention is NOT enabled! See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73561 [$($Results.Status)]"

#Return results
return $Results
