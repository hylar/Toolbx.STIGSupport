<#
.SYNOPSIS
    This checks for compliancy on V-73289.

    The Microsoft FTP service must not be installed unless required.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73289"

# Initial Variables
$Results = @{
    VulnID   = "V-73289"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$roleName = "FTP Server"
$role = Get-WindowsFeature | ? {$_.DisplayName -eq $roleName}
if ($role.Installed -eq 0) {
    $Results.Status = "NotAFinding"
    $Results.Details = "The $roleName role is not installed. See comments for details."
}
if ($role.Installed -eq 1)  {
    $Results.Status = "Open"
    $Results.Details = "Fail. The $roleName role is installed. See comments for details."
}
$Results.Comments = $role | Out-String

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73289 [$($Results.Status)]"

#Return results
return $Results
