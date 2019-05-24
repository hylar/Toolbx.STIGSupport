<#
.SYNOPSIS
    This checks for compliancy on V-73271.

    Software certificate installation files must be removed from Windows Server 2016.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73271"

# Initial Variables
$Results = @{
    VulnID   = "V-73271"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$drives=(Get-Volume | ?{$_.DriveType -eq 'Fixed' -and $_.DriveLetter.Length -eq 1})
$certs=@()
foreach($drive in $drives){
    $error.Clear
    $files=(Get-ChildItem -LiteralPath (($drive.DriveLetter)+':\') -File -Recurse).Name
    $certs+=$files -match [regex]::escape(".pfx")
    $certs+=$files -match [regex]::escape(".p12")
    if(($error | Select -First 1).Exception -like "System.UnauthorizedAccessException: Access to the path*"){
        $certs+=($error | Select -First 1).Exception
    }
}
if($certs){
    $Results.Status="Open"
    $Results.Details="Cert file report:"+($certs | Out-String)
}else{
    $Results.Status="NotAFinding"
    $Results.Details="No cert files found on fixed drives."
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73271 [$($Results.Status)]"

#Return results
return $Results
