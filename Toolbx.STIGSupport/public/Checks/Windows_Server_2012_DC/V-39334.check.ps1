<#
.SYNOPSIS
    This checks for compliancy on V-39334.

    Domain controllers must have a PKI server certificate.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-39334"

# Initial Variables
$Results = @{
    VulnID   = "V-39334"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
if ($PreCheck.hostType -eq "Domain Controller") {
    $certs = (Get-ChildItem -Path Cert:Localmachine\my)
    if ($certs) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Verified machine has a personal certificate. See comments for details."
        $Results.Comments = ("-=Local Certs=-`r`n"+($certs.Issuer | Select Subject, Issuer | Format-List | Out-String))
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Cannot find a personal certificate on this machine!"
    }
}
else {
    $Results.Status = "Not_Applicable"
    $Results.Details = "Check only applies to domain controllers."
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-39334 [$($Results.Status)]"

#Return results
return $Results
