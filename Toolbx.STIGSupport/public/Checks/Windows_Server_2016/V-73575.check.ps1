<#
.SYNOPSIS
    This checks for compliancy on V-73575.

    Remote Desktop Services must be configured with the client connection encryption set to High Level.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73575"

# Initial Variables
$Results = @{
    VulnID   = "V-73575"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty 'HKLM:\\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' -Name MinEncryptionLevel)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.MinEncryptionLevel
    if ($value -eq 3) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Remote Desktop Services have client connection encryption set to High. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Remote Desktop Services do NOT have client connection encryption set to High! See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73575 [$($Results.Status)]"

#Return results
return $Results
