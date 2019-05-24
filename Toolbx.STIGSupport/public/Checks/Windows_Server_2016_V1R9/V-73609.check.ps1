<#
.SYNOPSIS
    This checks for compliancy on V-73609.

    The US DoD CCEB Interoperability Root CA cross-certificates must be installed in the Untrusted Certificates Store on unclassified systems.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param(`$PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73609"

# Initial Variables
$Results = @{
    VulnID   = "V-73609"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$certs=(Get-ChildItem -Path Cert:Localmachine\disallowed | Where Issuer -Like "*CCEB Interoperability*" | FL Subject, Issuer, Thumbprint) | Out-String
if(
    $certs -match "CN=DoD Root CA 2, OU=PKI, OU=DoD, O=U.S. Government, C=US" -and
    $certs -match "CN=US DoD CCEB Interoperability Root CA 1, OU=PKI, OU=DoD, O=U.S. Government, C=US" -and
    $certs -match "DA36FAF56B2F6FBA1604F5BE46D864C9FA013BA3"
){
    $Results.Details="$certs"
    $Results.Status="NotAFinding"
}else{
    $Results.Details="$key"
    $Results.Status="Open"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73609 [$($Results.Status)]"

#Return results
return $Results
