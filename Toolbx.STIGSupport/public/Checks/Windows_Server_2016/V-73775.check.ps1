<#
.SYNOPSIS
    This checks for compliancy on V-73775.

    The Deny log on through Remote Desktop Services user right on member servers must be configured to prevent access from highly privileged domain accounts and all local accounts on domain systems and from unauthenticated access on all systems.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73775"

# Initial Variables
$Results = @{
    VulnID   = "V-73775"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
if ($PreCheck.HostType -ne "Domain Controller") {
    $right = $PreCheck.userRights -match "SeDenyRemoteInteractiveLogonRight"
    if (!$right) {
        $Results.Details = "Unable to find entry in user rights!"
        $Results.Status = "Open"
    }
    else {
        [string]$value = $right.Accountlist
        if ($PreCheck.HostType -eq "Non-Domain" -and $value -match "Guests") {
            $Results.Details = ($right | Out-String)
            $Results.Status = "NotAFinding"
        }
        else {
            if (
                ($value -match [regex]::escape($PreCheck.domain + "\Domain Admins") -or $value -match [regex]::escape($PreCheck.domain + "\Domain Server Admins")) -and
                ($value -match [regex]::escape($PreCheck.domain + "\Enterprise Admins") -or $value -match [regex]::escape($PreCheck.domain + "\Enterprise Server Admins")) -and
                $value -match "Local account" -and
                $value -match "Guests"
            ) {
                $Results.Status = "NotAFinding"
                $Results.Details = "Verified Domain Admins and Enterprise Admins groups are denied logon. See comments for details."
                $Results.Comments = ($right | Out-String)
            }
            else {
                $Results.Status = "Open"
                $Results.Details = "Unable to find Domain Admins and Entrprise Admins groups, please review! See comments for details."
                $Results.Comments = ($right | Out-String)
            }
        }
    }
}
else {
    $Results.Details = "Check is NOT applicable to Domain Controllers."
    $Results.Status = "Not_Applicable"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73775 [$($Results.Status)]"

#Return results
return $Results
