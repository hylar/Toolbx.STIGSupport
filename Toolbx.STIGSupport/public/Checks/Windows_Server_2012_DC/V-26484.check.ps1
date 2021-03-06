<#
.SYNOPSIS
    This checks for compliancy on V-26484.

    The Deny log on as a service user right on member servers must be configured to prevent access from highly privileged domain accounts on domain systems.  No other groups or accounts must be assigned this right.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-26484"

# Initial Variables
$Results = @{
    VulnID   = "V-26484"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
if ($PreCheck.HostType -ne "Domain Controller") {
    $right = $PreCheck.userRights -match "SeDenyServiceLogonRight"
    if (!$right) {
        $Results.Details = "Unable to find entry in user rights!"
        $Results.Status = "Open"
    }
    else {
        [string]$value = $right.Accountlist
        if ($PreCheck.HostType -eq "Non-Domain" -and $value.Length -gt 0) {
            $Results.Details = "Verified no users are denied logon as a service. See comments for details."
            $Results.Comments = ($right | Out-String)
            $Results.Status = "NotAFinding"
        }
        else {
            if (
                ($value -match [regex]::escape($PreCheck.domain + "\Domain Admins") -or $value -match [regex]::escape($PreCheck.domain + "\Domain Server Admins")) -and
                ($value -match [regex]::escape($PreCheck.domain + "\Enterprise Admins") -or $value -match [regex]::escape($PreCheck.domain + "\Enterprise Server Admins"))
            ) {
                $Results.Status = "NotAFinding"
                $Results.Details = "Verified Domain Admins and Enterprise Admins are denied logon as a service. See comments for details."
                $Results.Comments = ($right | Out-String)
            }
            else {
                $Results.Status = "Open"
                $Results.Details = "Unable to verify correct users are denied logon as a service; Please review! See comments for details."
                $Results.Comments = ($right | Out-String)
            }
        }
    }
}
else {
    $right = $PreCheck.userRights -match "SeDenyServiceLogonRight"
    if (!$right) {
        $Results.Details = "Unable to find entry in user rights!"
        $Results.Status = "Open"
    }
    else {
        [string]$value = $right.Accountlist
        if ($value.Length -eq 0) {
            $Results.Status = "NotAFinding"
            $Results.Details = "Verified no users are denied logon as a service. See comments for details."
            $Results.Comments = ($right | Out-String)
        }
            else {
            $Results.Status = "Open"
            $Results.Details = "Unable to verify correct users are denied logon as a service; Please review! See comments for details."
            $Results.Comments = ($right | Out-String)
        }
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-26484 [$($Results.Status)]"

#Return results
return $Results
