<#
.SYNOPSIS
    This checks for compliancy on V-73701.

    Windows Server 2016 must be configured to use FIPS-compliant algorithms for encryption

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73701"

# Initial Variables
$Results = @{
    VulnID   = "V-73701"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty 'HKLM:\\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\' -Name Enabled)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.Enabled
    if ($value -eq 1) {
        $Results.Status = "NotAFinding"
        $Results.Details = "FIPS-compliant algorithms are enabled. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "FIPS-compliant algorithms are NOT enabled! See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73701 [$($Results.Status)]"

#Return results
return $Results
