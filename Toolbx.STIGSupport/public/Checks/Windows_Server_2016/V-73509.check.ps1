<#
.SYNOPSIS
    This checks for compliancy on V-73509.

    Hardened UNC paths must be defined to require mutual authentication and integrity for at least the \\*\SYSVOL and \\*\NETLOGON shares.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73509"

# Initial Variables
$Results = @{
    VulnID   = "V-73509"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\ -Name \\*\NETLOGON)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}else {
    [string]$value = $key | select \\*\NETLOGON | Out-String
    if ($value -match "RequireMutualAuthentication=1, RequireIntegrity=1" -or $value -match "RequireMutualAuthentication=1,RequireIntegrity=1") {
        $Results.Status = "NotAFinding"
        $Results.Details = "UNC paths for NETLOGON are hardened. See comments for details."
        $Results.Comments = (($key | Select \\*\NETLOGON,PSPath) | Out-String) -replace [regex]::escape("Microsoft.PowerShell.Core\Registry::"),"" -replace "`r`n`r`n",""
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "UNC paths for NETLOGON are NOT hardened! See comments for details."
        $Results.Comments = (($key | Select \\*\NETLOGON,PSPath) | Out-String) -replace [regex]::escape("Microsoft.PowerShell.Core\Registry::"),"" -replace "`r`n`r`n",""
    }
}

$key2 = (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\ -Name \\*\SYSVOL)
if (!$key) {
    $Results.Details += "`r`nRegistry key not found!"
    $Results.Status = "Open"
}
else {
    [string]$value = $key2 | select \\*\SYSVOL | Out-String
    if ($value -match "RequireMutualAuthentication=1, RequireIntegrity=1" -or $value -match "RequireMutualAuthentication=1,RequireIntegrity=1") {
        $Results.Details += "`r`nUNC paths for SYSVOL are hardened. See comments for details."
        $Results.Comments += ("`r`n"+((($key2 | Select \\*\SYSVOL,PSPath) | Out-String) -replace [regex]::escape("Microsoft.PowerShell.Core\Registry::"),"") -replace "`r`n`r`n","")
    }    else {
        $Results.Status = "Open"
        $Results.Details += "`r`nUNC paths for SYSVOL are NOT hardened! See comments for details."
        $Results.Comments += ("`r`n"+((($key2 | Select \\*\SYSVOL,PSPath) | Out-String) -replace [regex]::escape("Microsoft.PowerShell.Core\Registry::"),"") -replace "`r`n`r`n","")
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73509 [$($Results.Status)]"

#Return results
return $Results
