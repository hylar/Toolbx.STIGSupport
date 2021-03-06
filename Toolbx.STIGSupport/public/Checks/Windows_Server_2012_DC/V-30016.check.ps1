<#
.SYNOPSIS
    This checks for compliancy on V-30016.

    Unauthorized accounts must not have the Add workstations to domain user right.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-30016"

# Initial Variables
$Results = @{
    VulnID   = "V-30016"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
if ($PreCheck.hostType -eq "Domain Controller") {
    $right = $PreCheck.userRights -match "SeMachineAccountPrivilege"
    if (!$right) {
        $Results.Details = "Unable to find entry in user rights!"
        $Results.Status = "Open"
    }
    else {
        [string]$value = $right.Accountlist
        if ($value -match "Administrators" -and ($value -replace "Administrators", '' -replace " ", "").Length -eq 0) {
            $Results.Status = "NotAFinding"
            $Results.Details = "Verified take ownership of files or other objects right is only given to Administrators. See comments for details."
            $Results.Comments = ($right | Out-String)
        }
        $Results.Comments = ($right | Out-String)
        }
        else {
            $Results.Status = "Open"
            $Results.Details = "Take ownership of files or other objects right contains more users/groups than Administrators; Please review! See comments for details."
            $Results.Comments = ($right | Out-String)
        }
    }
}
else {
    $Results.Status = "Not_Applicable"
    $Results.Details = "Check only applies to Domain Controllers."
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-30016 [$($Results.Status)]"

#Return results
return $Results
