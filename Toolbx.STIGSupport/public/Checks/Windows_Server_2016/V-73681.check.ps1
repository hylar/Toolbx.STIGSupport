<#
.SYNOPSIS
    This checks for compliancy on V-73681.

    NTLM must be prevented from falling back to a Null session.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73681"

# Initial Variables
$Results = @{
    VulnID   = "V-73681"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty 'HKLM:\\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0\' -Name allownullsessionfallback)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.allownullsessionfallback
    if ($value -eq 0) {
        $Results.Status = "NotAFinding"
        $Results.Details = "NTLM is not premitted to fallback to a null session. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Null session fallback NOT restricted! See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73681 [$($Results.Status)]"

#Return results
return $Results
