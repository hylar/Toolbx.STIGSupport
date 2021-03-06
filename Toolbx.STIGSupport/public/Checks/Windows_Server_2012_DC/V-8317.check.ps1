<#
.SYNOPSIS
    This checks for compliancy on V-8317.

    Data files owned by users must be on a different logical partition from the directory server data files.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-8317"

# Initial Variables
$Results = @{
    VulnID   = "V-8317"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
if ($PreCheck.hostType -eq "Domain Controller") {
    [string]$keyPath = "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters"
    [string]$valueName = "Database log files path"
    [string]$valueName2 = "DSA Database file"
    $key = (Get-ItemProperty $keyPath -Name $valueName -ErrorAction SilentlyContinue)
    $key2 = (Get-ItemProperty $keyPath -Name $valueName2 -ErrorAction SilentlyContinue)
    [array]$path = ($key.$valueName -split "\\" | Select-Object -First 1)
    $path2 = ($key2.$valueName2 -split "\\" | Select-Object -First 1)
    if ($path2 -ne $path) {
        $path += $path2
    }
    $shares = net share
    $sharesFilter = $shares | Where-Object {
        $_ -notlike "Share name*" -and
        $_ -notlike "-------------*" -and
        $_ -notlike "C$ *" -and
        $_ -notlike "ADMIN$ *" -and
        $_ -notlike "IPC$ *" -and
        $_ -notlike "NETLOGON *" -and
        $_ -notlike "SYSVOL *" -and
        $_ -notlike "The command completed successfully." -and
        $_ -ne "" -and
        $_ -like "*$path\\*"
    }
    [int]$fail = 0
    foreach ($p in $path) {
        if ($shares -match $p) {
            [int]$fail = 1
        }
    }
    if ($fail -eq 0) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Only system and administrator shares exist on drives with directory service data. See comments for details."
        $Results.Comments = $shares | Out-String
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Found one or more non-system, non-administrative shares on drives with directory service data; Please review! See comments for details."
        $Results.Comments = $shares | Out-String
    }
}
else {
    $Results.Status = "Not_Applicable"
    $Results.Details = "Check is only valid for Domain Controllers."
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-8317 [$($Results.Status)]"

#Return results
return $Results
