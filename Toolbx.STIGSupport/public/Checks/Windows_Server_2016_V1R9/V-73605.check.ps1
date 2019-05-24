<#
.SYNOPSIS
    This checks for compliancy on V-73605.

    The DoD Root CA certificates must be installed in the Trusted Root Store.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param(`$PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73605"

# Initial Variables
$Results = @{
    VulnID   = "V-73605"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$certs=(Get-ChildItem -Path Cert:Localmachine\root | Where Subject -Like "*DoD*" | FL Subject, Thumbprint) | Out-String
if(
    $certs -match "CN=DoD Root CA 2, OU=PKI, OU=DoD, O=U.S. Government, C=US" -and
    $certs -match "8C941B34EA1EA6ED9AE2BC54CF687252B4C9B561" -and
    $certs -match "CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US" -and
    $certs -match "D73CA91102A2204A36459ED32213B467D7CE97FB" -and
    $certs -match "CN=DoD Root CA 4, OU=PKI, OU=DoD, O=U.S. Government, C=US" -and
    $certs -match "B8269F25DBD937ECAFD4C35A9838571723F2D026"
){
    $Results.Details="$certs"
    $Results.Status="NotAFinding"
}else{
    $Results.Details="$key"
    $Results.Status="Open"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73605 [$($Results.Status)]"

#Return results
return $Results
