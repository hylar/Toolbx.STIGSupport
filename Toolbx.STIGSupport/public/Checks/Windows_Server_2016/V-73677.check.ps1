<#
.SYNOPSIS
    This checks for compliancy on V-73677.

    Remote calls to the Security Account Manager (SAM) must be restricted to Administrators.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73677"

# Initial Variables
$Results = @{
    VulnID   = "V-73677"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty 'HKLM:\\SYSTEM\CurrentControlSet\Control\Lsa\' -Name RestrictRemoteSAM)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [string]$value = $key.RestrictRemoteSAM
    if ($value -eq "O:BAG:BAD:(A;;RC;;;BA)") {
        $Results.Status = "NotAFinding"
        $Results.Details = "Only administrators can make remote calls to the SAM. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Remote calls to the SAM are NOT restricted to only administrators! See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73677 [$($Results.Status)]"

#Return results
return $Results
