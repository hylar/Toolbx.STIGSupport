<#
.SYNOPSIS
    This checks for compliancy on V-31026.

    .NET default proxy settings must be reviewed and approved.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-31026"

# Initial Variables
$Results = @{
    VulnID   = "V-31026"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

$Found = $false;

#Perform necessary check
$FullFileList = @() + $PreCheck.EXEConfigs
$FullFileList += $PreCheck.MachineConfigs

$FullFileList | ForEach-Object {

    Write-Verbose "[$($MyInvocation.MyCommand)] Searching $_"

    $data = (Get-Content $_  -ErrorAction SilentlyContinue) -match '(?i)<\s*etwEnable[\w\s="]*enabled\s*=\s*"false"(?-i)'

    if ($data) { $Results.Comments = "$($Results.Comments)`n" + "[Finding] $_" }

}

if (-not $Found) {
    $Results.Details = "No files were found with Event tracing for Windows (ETW) disabled."
    $Results.Status = "NotAFinding"
}
else {
    $Results.Details = "Files were found with Event tracing for Windows (ETW) disabled. See comments for a list."
    $Results.Status = "Open"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-31026 [$($Results.Status)]"

#Return results
return $Results