<#
.SYNOPSIS
    This checks for compliancy on V-73771.

    The Deny log on locally user right on member servers must be configured to prevent access from highly privileged domain accounts on domain systems and from unauthenticated access on all systems.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73771"

# Initial Variables
$Results = @{
    VulnID   = "V-73771"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
if ($PreCheck.HostType -ne "Domain Controller") {
    $right = $PreCheck.userRights -match "SeDenyInteractiveLogonRight"
    if (!$right) {
        $Results.Details = "Unable to find entry in user rights!"
        $Results.Status = "Open"
    }
    else {
        [string]$value = $right.Accountlist
        if (
            ($value -match [regex]::escape($PreCheck.domain + "\Domain Admins") -or $value -match [regex]::escape($PreCheck.domain + "\Domain Server Admins")) -and
            ($value -match [regex]::escape($PreCheck.domain + "\Enterprise Admins") -or $value -match [regex]::escape($PreCheck.domain + "\Enterprise Server Admins")) -and
            $value -match "Guests" -and
            $PreCheck.HostType -eq "Member Server"
        ) {
            $Results.Status = "NotAFinding"
            $Results.Details = "Verified Domain Admins, Enterprise Admins, and Guests groups are denied logon. See comments for details."
            $Results.Comments = ($right | Out-String)
        }
        elseif (
            $value -match "Guests" -and
            $PreCheck.HostType -eq "Non-Domain"
        ) {
            $Results.Status = "NotAFinding"
            $Results.Details = "Verified Guests group is denied logon. See comments for details."
            $Results.Comments = ($right | Out-String)
        }
        else {
            $Results.Status = "Open"
            $Results.Details = "Unable to verify all required groups are denied logon, please review! See comments for details."
            $Results.Comments = ($right | Out-String)
        }
    }
}
else {
    $Results.Details = "Check is NOT applicable to Domain Controllers."
    $Results.Status = "Not_Applicable"
}
Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73771 [$($Results.Status)]"

#Return results
return $Results
