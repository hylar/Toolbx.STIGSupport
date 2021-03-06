<#
.SYNOPSIS
    This checks for compliancy on V-73717.

    User Account Control must only elevate UIAccess applications that are installed in secure locations.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73717"

# Initial Variables
$Results = @{
    VulnID   = "V-73717"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty 'HKLM:\\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\' -Name EnableSecureUIAPaths)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.EnableSecureUIAPaths
    if ($value -eq 1) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Elevation allowed only when UIAccess applications that are installed in secure locations. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Elevation does NOT require secure locations. See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73717 [$($Results.Status)]"

#Return results
return $Results
