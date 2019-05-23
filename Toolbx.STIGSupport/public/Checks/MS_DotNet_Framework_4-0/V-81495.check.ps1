<#
.SYNOPSIS
    This checks for compliancy on V-81495.

    Trust must be established prior to enabling the loading of remote code in .Net 4.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-81495"

# Initial Variables
$Results = @{
    VulnID   = "V-81495"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

$Found = $false;

#Perform necessary check
$Key32 = Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319\SchUseStrongCrypto" -Name "SchUseStrongCrypto" -ErrorAction SilentlyContinue
$Key64 = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319\SchUseStrongCrypto" -Name "SchUseStrongCrypto" -ErrorAction SilentlyContinue

if ($null -eq $Key32) {
    $Results.Comments = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319\SchUseStrongCrypto does not exist for WOW6432Node.`r`n"
    $found = $true
}
elseif ($Key32.SchUseStrongCrypto -ne 1) {
    $Results.Comments = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319\SchUseStrongCrypto is not set to '1' for WOW6432Node.`r`n"
    $found = $true
}
else {
    $Results.Comments = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319\SchUseStrongCrypto is good.`r`n"
}

if ($null -eq $Key64) {
    $Results.Comments= "$($Results.Comments)`r`n'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319\SchUseStrongCrypto' does not exist for native software node.`r`n"
    $found = $true
} elseif ($Key64.SchUseStrongCrypto -ne 1) {
    $Results.Comments= "$($Results.Comments)`r`n'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319\SchUseStrongCrypto' is not set to '1' for native software node.`r`n"
    $found = $true
} else {
    $Results.Comments = "$($Results.Comments)`r`nHKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319\SchUseStrongCrypto is good.`r`n"
}


if (-not $Found) {
    $Results.Details = "TLS RC4 cipher in .Net is Disabled"
    $Results.Status = "NotAFinding"
}
else {
    $Results.Details = "TLS RC4 cipher in .Net is enabled. See comments for a list."
    $Results.Status = "Open"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-81495 [$($Results.Status)]"

#Return results
return $Results