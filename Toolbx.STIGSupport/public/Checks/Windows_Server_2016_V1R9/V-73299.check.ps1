<#
.SYNOPSIS
    This checks for compliancy on V-73299.

    The Server Message Block (SMB) v1 protocol must be uninstalled.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73299"

# Initial Variables
$Results = @{
    VulnID   = "V-73299"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$roleName = "FS-SMB1"
$role = Get-WindowsFeature | ? {$_.Name -eq $roleName}
if ($role.Installed -eq 0) {
    $Results.Status = "NotAFinding"
    $Results.Details = "The $roleName role is not installed. See comments."
}
if ($role.Installed -eq 1)  {
    $Results.Status = "Open"
    $Results.Details = "Fail. The $roleName role is installed. See comments."
}
$Results.Comments = $role

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73299 [$($Results.Status)]"

#Return results
return $Results
