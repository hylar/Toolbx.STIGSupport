<#
.SYNOPSIS
    This checks for compliancy on V-73587.

    Users must be notified if a web-based program attempts to install software.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73587"

# Initial Variables
$Results = @{
    VulnID   = "V-73587"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\' -Name SafeForScripting)
if (!$key) {
    $Results.Details = "Registry key was not found."
    $Results.Status = "NotAFinding"
}
else {
    [int]$value = $key.SafeForScripting
    if ($value -eq 0) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Users will be prompted for web-based installers. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Web-based installers are ALLOWED to continue without prompt!. See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73587 [$($Results.Status)]"

#Return results
return $Results
