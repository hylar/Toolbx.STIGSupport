<#
.SYNOPSIS
    This checks for compliancy on V-15823.

    Software certificate installation files must be removed from Windows 2012/2012 R2.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-15823"

# Initial Variables
$Results = @{
    VulnID   = "V-15823"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$drives = (Get-Volume | ? {$_.DriveType -eq 'Fixed' -and $_.DriveLetter.Length -eq 1})
$certs = @()
$warning = @()
$ErrorActionPreference = "SilentlyContinue"
foreach ($drive in $drives) {
    $error.Clear
    $files = (Get-ChildItem -LiteralPath (($drive.DriveLetter) + ':\') -File -Recurse) | Select FullName
    if($files -match [regex]::escape(".pfx")){$certs += $files -match [regex]::escape(".pfx")}
    if($files -match [regex]::escape(".p12")){$certs += $files -match [regex]::escape(".p12")}
    #Logs errors in output (will cause failure)
    if (($error | Select -First 1).Exception -like "*Access to the path '*' is denied.*") {
        $warning += (($error | Select -First 1).Exception | Out-String)
    }
}
$ErrorActionPreference = "Continue"
if ($certs) {
    $Results.Status = "Open"
    $Results.Details = "Certificate files were found on fixed drives for this machine. See comments for details."
    $Results.Comments = ("Cert file report:`r`n" + ($certs.FullName | Out-String) + "`r`nNo rights to scan some locations:`r`n "+$warning)
}
else {
    $Results.Status = "NotAFinding"
    $Results.Details = "No cert files found on fixed drives."
    if ($warning) {
        $Results.Comments = "No rights to scan some locations:`r`n "+$warning
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-15823 [$($Results.Status)]"

#Return results
return $Results
