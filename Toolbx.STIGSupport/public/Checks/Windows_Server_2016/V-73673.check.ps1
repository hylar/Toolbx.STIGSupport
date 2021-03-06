<#
.SYNOPSIS
    This checks for compliancy on V-73673.

    Windows Server 2016 must be configured to prevent anonymous users from having the same permissions as the Everyone group.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73673"

# Initial Variables
$Results = @{
    VulnID   = "V-73673"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty 'HKLM:\\SYSTEM\CurrentControlSet\Control\Lsa\' -Name EveryoneIncludesAnonymous)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.EveryoneIncludesAnonymous
    if ($value -eq 0) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Anonymous users are not granted Everyone permissions. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Anonymous users ARE granted Everyone permissions! See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73673 [$($Results.Status)]"

#Return results
return $Results
