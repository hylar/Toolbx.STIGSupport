<#
.SYNOPSIS
    This checks for compliancy on V-7070.

    Remoting Services HTTP channels must utilize authentication and encryption.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-7070"

# Initial Variables
$Results = @{
    VulnID   = "V-7070"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

[bool]$Found = $false;

#Perform necessary check
$FullFileList = @() + $PreCheck.EXEConfigs
$FullFileList += $PreCheck.MachineConfigs

$FullFileList | ForEach-Object {

    Write-Verbose "[$($MyInvocation.MyCommand)] Searching $_"

    $Content = (Get-Content $_ )
    $subresult = $Content -match '(?i)typefilterlevel\s*=\s*"full"(?-i)'; #match typefilterleve ="full"
    $subresult2 = $Content -match '(?i)<\s*channel[\w\s="]*ref\s*=\s*"http\s?(server)?"(?-i)'; #match <channel ref="http server"
    $subresult3 = $Content -match '(?i)<\s*channel[\w\s="]*port\s*=\s*"443"[\w\s="]*ref\s*=\s*"http\s?(server)?"(?-i)'; #match <channel port="443" ref="http server"
    $subresult4 = $Content -match '(?i)<\s*channel[\w\s="]*ref\s*=\s*"http\s?(server)?"[\w\s="]*port\s*=\s*"443"(?-i)'; #match <channel ref="http server" port="443"

    if ($subresult -and $subresult2 -and -not ($subresult3 -or $subresult4)) {
        $found = $true;
        $Results.Comments = "$($Results.Comments)`r`n" + $_.FullName
    }

}

if (-not $Found) {
    $Results.Details = "No files were found with the typefilterlevel set with incorrect channel settings."
    $Results.Status = "NotAFinding"
}
else {
    $Results.Details = "There are files with the typefilterlevel set with incorrect channel settings. See comments for a list."
    $Results.Status = "Open"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-7070 [$($Results.Status)]"

#Return results
return $Results