<#
.SYNOPSIS
    This checks for compliancy on V-26483.

    The Deny log on as a batch job user right on member servers must be configured to prevent access from highly privileged domain accounts on domain systems, and from unauthenticated access on all systems.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-26483"

# Initial Variables
$Results = @{
    VulnID   = "V-26483"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
if ($PreCheck.HostType -ne "Domain Controller") {
    $right = $PreCheck.userRights -match "SeDenyBatchLogonRight"
    if (!$right) {
        $Results.Details = "Unable to find entry in user rights!"
        $Results.Status = "Open"
    }
    else {
        [string]$value = $right.Accountlist
        if ($PreCheck.HostType -eq "Non-Domain" -and $value -match "Guests") {
            $Results.Details = "Verified Guests are denied logon as a batch job. See comments for details."
            $Results.Comments = ($right | Out-String)
            $Results.Status = "NotAFinding"
        }
        else {
            if (
                ($value -match [regex]::escape($PreCheck.domain + "\Domain Admins") -or $value -match [regex]::escape($PreCheck.domain + "\Domain Server Admins")) -and
                ($value -match [regex]::escape($PreCheck.domain + "\Enterprise Admins") -or $value -match [regex]::escape($PreCheck.domain + "\Enterprise Server Admins")) -and
                $value -match "Guests"
            ) {
                $Results.Status = "NotAFinding"
                $Results.Details = "Verified Domain Admins, Enterprise Admins, and Guests are denied logon as a batch job. See comments for details."
                $Results.Comments = ($right | Out-String)
            }
            else {
                $Results.Status = "Open"
                $Results.Details = "Unable to verify Domain Admins, Enterprise Admins, and Guests are denied logon as a batch job; Please review! See comments for details."
                $Results.Comments = ($right | Out-String)
            }
        }
    }
}
else {
    $right = $PreCheck.userRights -match "SeDenyBatchLogonRight"
    if (!$right) {
        $Results.Details = "Unable to find entry in user rights!"
        $Results.Status = "Open"
    }
    else {
        [string]$value = $right.Accountlist
        if ($value -match "Guests") {
            $Results.Details = "Verified Guests are denied logon as a batch job. See comments for details."
            $Results.Comments = ($right | Out-String)
            $Results.Status = "NotAFinding"
        }
        else {
            $Results.Status = "Open"
            $Results.Details = "Unable to verify Guests are denied logon as a batch job; Please review! See comments for details."
            $Results.Comments = ($right | Out-String)
        }
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-26483 [$($Results.Status)]"

#Return results
return $Results
