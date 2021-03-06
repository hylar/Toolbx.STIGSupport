<#
.SYNOPSIS
    This checks for compliancy on V-73581.

    Indexing of encrypted files must be turned off.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73581"

# Initial Variables
$Results = @{
    VulnID   = "V-73581"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty 'HKLM:\\SOFTWARE\Policies\Microsoft\Windows\Windows Search\' -Name AllowIndexingEncryptedStoresOrItems)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.AllowIndexingEncryptedStoresOrItems
    if ($value -eq 0) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Indexing of encrypted files is not allowed. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Indexing of encrypted files is ALLOWED! See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73581 [$($Results.Status)]"

#Return results
return $Results
