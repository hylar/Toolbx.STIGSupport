<#
.SYNOPSIS
    This checks for compliancy on V-73287.

    The Fax Server role must not be installed.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73287"

# Initial Variables
$Results = @{
    VulnID   = "V-73287"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$roleName = "Fax Server"
$role = Get-WindowsFeature | Where-Object {$_.DisplayName -eq $roleName}
if ($role.Installed -eq 0) {
    $Results.Status = "NotAFinding"
    $Results.Details = "The $roleName role is not installed. See comments for details."
}
if ($role.Installed -eq 1)  {
    $Results.Status = "Open"
    $Results.Details = "Fail. The $roleName role is installed. See comments for details."
}
$Results.Comments = $role | Out-String


Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73287 [$($Results.Status)]"

#Return results
return $Results
