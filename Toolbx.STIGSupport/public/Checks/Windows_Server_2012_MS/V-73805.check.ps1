<#
.SYNOPSIS
    This checks for compliancy on V-73805.

    The Server Message Block (SMB) v1 protocol must be disabled on Windows 2012 R2.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73805"

# Initial Variables
$Results = @{
    VulnID   = "V-73805"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$featureName = "SMB1Protocol"
$feature = Get-WindowsOptionalFeature -Online -FeatureName $featureName
if ($feature.State -eq 'Disabled') {
    $Results.Status = "NotAFinding"
    $Results.Details = "The SMB 1.0/CIFS File Sharing Support feature is not enabled. See comments for details."
}
else {
    $Results.Status = "Open"
    $Results.Details = "The SMB 1.0/CIFS File Sharing Support feature is enabled! See comments for details."
}
$Results.Comments = $feature | Select-Object FeatureName,DisplayName,State | Format-List | Out-String

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73805 [$($Results.Status)]"

#Return results
return $Results
