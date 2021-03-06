<#
.SYNOPSIS
    This checks for compliancy on V-73525.

    Group Policy objects must be reprocessed even if they have not changed.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73525"

# Initial Variables
$Results = @{
    VulnID   = "V-73525"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\' -Name NoGPOListChanges)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.NoGPOListChanges
    if ($value -eq 0) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Group policy objects will be reprocessed even if unchanged. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Group policy objects will NOT be reprocessed if unchanged! See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73525 [$($Results.Status)]"

#Return results
return $Results
