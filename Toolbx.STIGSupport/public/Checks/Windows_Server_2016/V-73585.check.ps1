<#
.SYNOPSIS
    This checks for compliancy on V-73585.

    The Windows Installer Always install with elevated privileges option must be disabled.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73585"

# Initial Variables
$Results = @{
    VulnID   = "V-73585"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty 'HKLM:\\SOFTWARE\Policies\Microsoft\Windows\Installer\' -Name AlwaysInstallElevated)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.AlwaysInstallElevated
    if ($value -eq 0) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Windows Installer is not set to always installed using elevated rights. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Windows Installer IS set to always installed using elevated rights. See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73585 [$($Results.Status)]"

#Return results
return $Results
