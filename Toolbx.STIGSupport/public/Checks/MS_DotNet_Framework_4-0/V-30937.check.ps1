<#
.SYNOPSIS
    This checks for compliancy on V-30937.

    .Net applications that invoke NetFx40_LegacySecurityPolicy must apply previous versions of .NET STIG guidance.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-30937"

# Initial Variables
$Results = @{
    VulnID   = "V-30937"
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

    if ((Get-Item -Path $_).Name -eq "caspol.exe.config") {
        #Specifically exempted, so skip to next item in foreach loop
        continue
    }

    Write-Debug "[$($MyInvocation.MyCommand)] Searching $_"

    # Match NetFx40_LegacySecurityPolicy enabled="true"
    If((Get-Content $_ -ErrorAction SilentlyContinue) -match '(?i)NetFx40_LegacySecurityPolicy\s*enabled\s*=\s*"true"(?-i)'){

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
    $Results.Details = "No files were found with legacy security enabled."
    $Results.Status = "NotAFinding"
}
else {
    $Results.Details = "Files were found with legacy security enabled. See comments for a list."
    $Results.Status = "Open"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-30937 [$($Results.Status)]"

#Return results
return $Results