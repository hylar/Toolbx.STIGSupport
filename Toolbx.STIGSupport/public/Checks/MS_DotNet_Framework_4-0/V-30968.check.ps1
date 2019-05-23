<#
.SYNOPSIS
    This checks for compliancy on V-30968.

    Trust must be established prior to enabling the loading of remote code in .Net 4.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-30968"

# Initial Variables
$Results = @{
    VulnID   = "V-30968"
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

    # Match <loadFromRemoteSources enabled="true"
    If((Get-Content $_ -ErrorAction SilentlyContinue) -match '(?i)<loadFromRemoteSources[\w\s="]*enabled\s*=\s*"true"(?-i)'){

        If($Results.Comments -eq ""){
            $Results.Comments = "Files were found with legacy security enabled:`r`n"
            $Results.Comments = "$($Results.Comments)`r`n" + $_
        }else{
            $Results.Comments = "$($Results.Comments)`r`n" + $_
        }

        $Found = $True
    }

}

if (-not $Found) {
    $Results.Details = "No files were found with loadFromRemoteSources enabled."
    $Results.Status = "NotAFinding"
}
else {
    $Results.Details = "Files were found with loadFromRemoteSources enabled. See comments for a list."
    $Results.Status = "Open"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-30968 [$($Results.Status)]"

#Return results
return $Results

<#
#TODO: Need to check if HBSS covers this then we can add a check to see if the agent is installed.

If the loadFromRemoteSources element is enabled ("loadFromRemoteSources enabled = true"),
and the remotely loaded application is not run in a sandboxed environment, or if OS based
software controls, such as AppLocker or Software Security Policies, are not utilized,
this is a finding.
#>