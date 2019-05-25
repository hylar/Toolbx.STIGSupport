<#
.SYNOPSIS
    This checks for compliancy on V-32025.

    Remoting Services TCP channels must utilize authentication and encryption.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-32025"

# Initial Variables
$Results = @{
    VulnID   = "V-32025"
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

    Write-Debug "[$($MyInvocation.MyCommand)] Searching $_"

    $content = (Get-Content $_ -ErrorAction SilentlyContinue)

    if ($content) {

        $result1 = $Content -match '(?i)typefilterlevel\s*=\s*"full"(?-i)'; #match typefilterlevel ="full"
        $result2 = $Content -match '(?i)<\s*channel[\w\s="]*ref\s*=\s*"tcp\s?(server)?"[\w\s="]*secure\s*=\s*"true"(?-i)'; #Check for <channel ref="tcp" secure="true"
        $result3 = $Content -match '(?i)<\s*channel[\w\s="]*secure\s*=\s*"true"[\w\s="]*ref\s*=\s*"tcp\s?(server)?"(?-i)'; #Check for <channel secure="true" ref="tcp"
        $result4 = $Content -match '(?i)<\s*channel[\w\s="]*ref\s*=\s*"tcp\s?(server)?"(?-i)'; #Check for <channel ref="tcp"
        $result5 = $Content -match '(?i)<\s*channel[\w\s="]*secure\s*=\s*"false"(?-i)'; #Check for <channel secure="false"

        #if anything is set to secure=false or if ref=tcp is detected but without a secure=true
        if ($result1 -and ($result5 -or ($result4 -and -not ($result3 -or $result2)))) {

            $Results.Comments = "$($Results.Comments)`n" + "$_"
            $found = $true

        }

    }

}

if (-not $Found) {
    $Results.Details = "No files were found with disabled encryption/integrity with typeFilter Full."
    $Results.Status = "NotAFinding"
}
else {
    $Results.Details = "Files were found with issues. See comments for a list."
    $Results.Status = "Open"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-32025 [$($Results.Status)]"

#Return results
return $Results