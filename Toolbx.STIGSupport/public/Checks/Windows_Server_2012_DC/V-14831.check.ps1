<#
.SYNOPSIS
    This checks for compliancy on V-14831.

    The directory service must be configured to terminate LDAP-based network connections to the directory server after five (5) minutes of inactivity.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-14831"

# Initial Variables
$Results = @{
    VulnID   = "V-14831"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
if ($PreCheck.hostType -eq "Domain Controller") {
    if (Test-Path $env:windir\system32\ntdsutil.exe) {
        $values = ntdsutil "LDAP policies" "connections" "connect to server $env:COMPUTERNAME" q "show values" q q
        [int]$idleTime = ($values -match "MaxConnIdleTime" | Out-String) -split "`t" | Select-Object -Last 1
        if ($idle -le 300) {
            $Results.Status = "NotAFinding"
            $Results.Details = "Idle timeout for LDAP network connections is set to $idleTime. See comments for details."
            $Results.Comments = $values | Out-String
        }
        else {
            $Results.Status = "Open"
            $Results.Details = "Idle timeout for LDAP network connections is set to $idleTime, instead of 300 or less; Please review! See comments for details."
            $Results.Comments = $values | Out-String
        }
    }
    else {
        $Results.Details = "Could not find ntdsutil.exe! Please review and test manually!"
    }
}
else {
    $Results.Status = "Not_Applicable"
    $Results.Details = "Check only applies to domain controllers."
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-14831 [$($Results.Status)]"

#Return results
return $Results
