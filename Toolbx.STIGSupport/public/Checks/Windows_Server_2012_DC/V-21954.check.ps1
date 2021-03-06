<#
.SYNOPSIS
    This checks for compliancy on V-21954.

    Kerberos encryption types must be configured to prevent the use of DES and RC4 encryption suites.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-21954"

# Initial Variables
$Results = @{
    VulnID   = "V-21954"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
[string]$keyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\"
[string]$valueName = "SupportedEncryptionTypes"
[int]$pass = 2147483640
$key = (Get-ItemProperty $keyPath -Name $valueName -ErrorAction SilentlyContinue)
if (!$key) {
    $Results.Details = "Registry value at $keyPath with name $valueName was not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.$valueName
    if ($value -eq $pass) {
        $Results.Status = "NotAFinding"
        $Results.Details = "$valueName is set to $value, indicating Kerberos only supports AES 128/256 HMAC SHA1 and future encryption. See comments for details."
    }
    elseif {
        $Results.Status = "Open"
        $Results.Details = "$valueName is set to $value instead of $pass; Indicating that RC4_HMAC_MD5 is still allowed! See comments for details."
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "$valueName is set to $value instead of $pass! See comments for details."
    }
}
$Results.Comments = "Path: "+($key.PSPath -replace [regex]::escape("Microsoft.PowerShell.Core\Registry::"),"")
$Results.Comments = ($Results.Comments+"`r`nName: "+$valueName)
$Results.Comments = ($Results.Comments+"`r`nValue: "+($key.$valueName | foreach{ ("`r`n"+$_) }))

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-21954 [$($Results.Status)]"

#Return results
return $Results
