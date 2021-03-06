<#
.SYNOPSIS
    This checks for compliancy on V-73631.

    Domain controllers must be configured to allow reset of machine account passwords.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73631"

# Initial Variables
$Results = @{
    VulnID   = "V-73631"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
if ($PreCheck.HostType -eq "Domain Controller") {
    $keyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\"
    $valueName = "RefusePasswordChange"
    $key = (Get-ItemProperty $keyPath -Name $valueName -ErrorAction SilentlyContinue)
    if (!$key) {
        $Results.Details = "Registry value at $keyPath with name $valueName was not found!"
        $Results.Status = "Open"
    }
    else {
        [int]$value = $key.valueName
        if ($value -eq 0) {
            $Results.Status = "NotAFinding"
            $Results.Details = "System allows reset of machine account passwords. See comments for details."
            $Results.Comments = $key | Out-String
        }
        else {
            $Results.Status = "Open"
            $Results.Details = "System does NOT allow reset of machine account passwords! See comments for details."
            $Results.Comments = $key | Out-String
        }
    }
}
else {
    $Results.Details = "Check is only applicable to Domain Controllers."
    $Results.Status = "Not_Applicable"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73631 [$($Results.Status)]"

#Return results
return $Results
