<#
.SYNOPSIS
    This checks for compliancy on V-14797.

    Anonymous access to the root DSE of a non-public directory must be disabled.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-14797"

# Initial Variables
$Results = @{
    VulnID   = "V-14797"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
#CHECK IS WIP
if ($PreCheck.hostType -eq "Domain Controller") {
    $Results.Status = "Open"
    $Results.Details = "This is a finding for Windows Domain Controllers at sensitive or classified networks. Risk can be mitigated by the following:"
    $Results.Details = $Results.Details + "`r`n-Use 802.1x authentication or MAC address restrictions on network hardware ports at the site."
    $Results.Details = $Results.Details + "`r`n-Configure firewall or host restrictions preventing access to ports 389, 636, 3268, and 3269 from systems not explicitly identified by domain (.mil) or IP address."
}
else {
    $Results.Status = "Not_Applicable"
    $Results.Details = "Check only applies to domain controllers."
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-14797 [$($Results.Status)]"

#Return results
return $Results
