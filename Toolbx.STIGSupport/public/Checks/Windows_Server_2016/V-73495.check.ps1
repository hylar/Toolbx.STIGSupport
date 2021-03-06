<#
.SYNOPSIS
    This checks for compliancy on V-73495.

    Local administrator accounts must have their privileged token filtered to prevent elevated privileges from being used over the network on domain systems.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73495"

# Initial Variables
$Results = @{
    VulnID   = "V-73495"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
if ($PreCheck.HostType -eq "Member Server") {
    $key = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ -Name LocalAccountTokenFilterPolicy)
    if (!$key) {
        $Results.Details = "Registry key not found!"
        $Results.Status = "Open"
    }
    else {
        [int]$value = $key.LocalAccountTokenFilterPolicy
        if ($value -eq 0) {
            $Results.Status = "NotAFinding"
            $Results.Details = "Local account token filter policy is disabled. See comments for details."
            $Results.Comments = $key | Out-String
        }
        else {
            $Results.Status = "Open"
            $Results.Details = "Local account token filter policy is NOT disabled. See comments for details."
            $Results.Comments = $key | Out-String
        }
    }
}
else {
    $Results.Status = "Not_Applicable"
    $Results.Details = "Check only applies to member servers."
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73495 [$($Results.Status)]"

#Return results
return $Results
