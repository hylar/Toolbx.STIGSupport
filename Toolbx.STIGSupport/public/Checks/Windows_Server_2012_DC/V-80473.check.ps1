<#
.SYNOPSIS
    This checks for compliancy on V-80473.

    Windows PowerShell must be updated to a version that supports script block logging on Windows 2012/2012 R2.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-80473"

# Initial Variables
$Results = @{
    VulnID   = "V-80473"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
[decimal]$version = (($PSVersionTable.PSVersion.Major | Out-String)+'.'+($PSVersionTable.PSVersion.Minor | Out-String)) -replace "`r`n",""
[decimal]$pass = 5.0
if ($version -ge $pass) {
    $Results.Status = "NotAFinding"
    $Results.Details = "Verified PowerShell is version $version. See details in comments."
}
else {
    $Results.Status = "Open"
    $Results.Details = "PowerShell is version $version, instead of $pass or greater; Please review! See details in comments."
}
$Results.Comments = ($PSVersionTable | Format-List | Out-String) -replace "`r`nValue","" -replace "`r`nName  : ",""

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-80473 [$($Results.Status)]"

#Return results
return $Results
