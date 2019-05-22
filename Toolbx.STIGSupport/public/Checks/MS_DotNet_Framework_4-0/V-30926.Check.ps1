<#
.SYNOPSIS
    This checks for compliancy on V-30926.

    The .NET CLR must be configured to use FIPS approved encryption modules.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-30926"

# Initial Variables
$Results = @{
    VulnID   = "V-30926"
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

    # Match <enforceFIPSPolicy enabled="false"
    If((Get-Content $_ -ErrorAction SilentlyContinue) -match '(?i)<enforceFIPSPolicy[\w\s="]*enabled\s*=\s*"false"(?-i)'){

        If($Results.Comments -eq ""){
            $Results.Comments = "Files Found with FIPS enabled:`r`n"
            $Results.Comments = "$($Results.Comments)`r`n" + $_
        }else{
            $Results.Comments = "$($Results.Comments)`r`n" + $_
        }

        $Found = $True
    }

}

if (-not $Found) {
    $Results.Details = "No files were found with an explicitly disabled FIPSPolicy."
    $Results.Status = "NotAFinding"
}
else {
    $Results.Details = "There are files with FIPS turned off. See comments for a list."
    $Results.Status = "Open"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-30926 [$($Results.Status)]"

#Return results
return $Results