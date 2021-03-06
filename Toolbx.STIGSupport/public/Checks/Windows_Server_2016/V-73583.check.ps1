<#
.SYNOPSIS
    This checks for compliancy on V-73583.

    Users must be prevented from changing installation options.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73583"

# Initial Variables
$Results = @{
    VulnID   = "V-73583"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty 'HKLM:\\SOFTWARE\Policies\Microsoft\Windows\Installer\' -Name EnableUserControl)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.EnableUserControl
    if ($value -eq 0) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Users are not allowed to change installation options. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Users ARE allowed to change installation options! See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73583 [$($Results.Status)]"

#Return results
return $Results
