<#
.SYNOPSIS
    This checks for compliancy on V-30972.

    .NET default proxy settings must be reviewed and approved.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-30972"

# Initial Variables
$Results = @{
    VulnID   = "V-30972"
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

    $data = (Get-Content $_  -ErrorAction SilentlyContinue) -match '(?i)<\s*defaultProxy(?-i)'

    if($data){

        [xml]$xml = Get-Content $_

        if($xml.configuration.'system.net'.defaultProxy.enabled -eq $true){

            if($xml.configuration.'system.net'.defaultProxy.HasChildNodes -eq $false){

                $Results.Comments = "[Not A Finding] $_"
                $Results.Comments = "$($Results.Comments)`n" + $xml.configuration.'system.net'.InnerXml.toString() + "`r`n"

            }else{

                $Results.Comments = "[Finding] $_"
                $Results.Comments = "$($Results.Comments)`n" + $xml.configuration.'system.net'.InnerXml.toString() + "`r`n"
                $found = $true

            }

        }else{

            $Results.Comments = "[Finding] $_"
            $Results.Comments = "$($Results.Comments)`n" + $xml.configuration.'system.net'.InnerXml.toString() + "`r`n"
            $found = $true

        }

    }

}

if (-not $Found) {
    $Results.Details = "No files were found with .Net Default proxy settings enabled."
    $Results.Status = "NotAFinding"
}
else {
    $Results.Details = "Files were found with .Net Default proxy settings. See comments for a list."
    $Results.Status = "Open"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-30972 [$($Results.Status)]"

#Return results
return $Results