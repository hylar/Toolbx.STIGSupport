<#
.SYNOPSIS
    This checks for compliancy on V-3472.

    The time service must synchronize with an appropriate DoD time source.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-3472"

# Initial Variables
$Results = @{
    VulnID   = "V-3472"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
[string]$keyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters"
[int]$pass = 1
$key = (Get-ItemProperty $keyPath -ErrorAction SilentlyContinue)
if (!$key) {
    $Results.Details = "Registry value at $keyPath with name $valueName was not found!"
    $Results.Status = "Open"
}
else {
    if ($key.Type -eq "NT5DS" -and $PreCheck.hostType -ne "Domain Controller") {
        $Results.Status = "NotAFinding"
        $Results.Details = "Time source is set to NT5DS, indicating time is synchronized with domain controllers. See comments for details."
    }
    elseif ($key.Type -eq "NTP" -and ($key.NtpServer -like "*.mil" -or $key.NtpServer -like "*.gov")) {
        $Results.Details = "Time source is set to NTP server '"+$key.NtpServer+"', please verify this is a valid DoD time server. See comments for details."
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Time source is set to NTP server '"+$key.NtpServer+"', please verify this is a valid DoD time server! See comments for details."
    }
}
$Results.Comments = $key | Select-Object NtpServer,Type,ServiceDll,PSParentPath | Format-List | Out-String

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-3472 [$($Results.Status)]"

#Return results
return $Results
