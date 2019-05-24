<#
.SYNOPSIS
    This checks for compliancy on V-73607.

    The DoD Interoperability Root CA cross-certificates must be installed in the Untrusted Certificates Store on unclassified systems.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param(`$PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73607"

# Initial Variables
$Results = @{
    VulnID   = "V-73607"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$certs=(Get-ChildItem -Path Cert:Localmachine\disallowed | Where {$_.Issuer -Like "*DoD Interoperability*" -and $_.Subject -Like "*DoD*"} | FL Subject, Issuer, Thumbprint) | Out-String
if(
    $certs -match "CN=DoD Root CA 2, OU=PKI, OU=DoD, O=U.S. Government, C=US" -and
    $certs -match "CN=DoD Interoperability Root CA 1, OU=PKI, OU=DoD, O=U.S. Government, C=US" -and
    $certs -match "22BBE981F0694D246CC1472ED2B021DC8540A22F" -and
    $certs -match "CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US" -and
    $certs -match "CN=DoD Interoperability Root CA 2, OU=PKI, OU=DoD, O=U.S. Government, C=US" -and
    $certs -match "FFAD03329B9E527A43EEC66A56F9CBB5393E6E13" -and
    $certs -match "CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US" -and
    $certs -match "CN=DoD Interoperability Root CA 2, OU=PKI, OU=DoD, O=U.S. Government, C=US" -and
    $certs -match "FCE1B1E25374DD94F5935BEB86CA643D8C8D1FF4"
){
    $Results.Details="$certs"
    $Results.Status="NotAFinding"
}else{
    $Results.Details="$key"
    $Results.Status="Open"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73607 [$($Results.Status)]"

#Return results
return $Results
