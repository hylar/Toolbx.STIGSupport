<#
.SYNOPSIS
    This checks for compliancy on V-73541.

    Unauthenticated Remote Procedure Call (RPC) clients must be restricted from connecting to the RPC server.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73541"

# Initial Variables
$Results = @{
    VulnID   = "V-73541"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$key = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc\' -Name RestrictRemoteClients)
if (!$key) {
    $Results.Details = "Registry key not found!"
    $Results.Status = "Open"
}
else {
    [int]$value = $key.RestrictRemoteClients
    if ($value -eq 1) {
        $Results.Status = "NotAFinding"
        $Results.Details = "System does not allow unauthenticated RDC clients. See comments for details."
        $Results.Comments = $key | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "System ALLOWS unauthenticated RDC clients! See comments for details."
        $Results.Comments = $key | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73541 [$($Results.Status)]"

#Return results
return $Results
