<#
.SYNOPSIS
    This checks for compliancy on V-26470.

    The Access this computer from the network user right must only be assigned to the Administrators and Authenticated Users groups on member servers.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-26470"

# Initial Variables
$Results = @{
    VulnID   = "V-26470"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$right = $PreCheck.userRights -match "SeNetworkLogonRight"
if (!$right) {
    $Results.Details = "Unable to find entry in user rights!"
    $Results.Status = "Open"
}
else {
    [string]$value = $right.Accountlist
    if ($PreCheck.hostType -eq "Domain Controller") {
        if (($value -replace "Administrators", '' -replace "Authenticated Users", '' -replace "Enterprise Domain Controllers", '' -replace " ", "").Length -eq 0) {
            $Results.Status = "NotAFinding"
            $Results.Details = "Verified access this computer from the network right is only given to Administrators, Authenticated Users, and Enterprise Domain Controllers. See comments for details."
            $Results.Comments = ($right | Out-String)
        }
        else {
            $Results.Status = "Open"
            $Results.Details = "Access this computer from the network right contains more users/groups than Administrators, Authenticated Users, and Enterprise Domain Controllers; Please review! See comments for details."
            $Results.Comments = ($right | Out-String)
        }
    }
    else{
        if (($value -replace "Administrators", '' -replace "Authenticated Users", '' -replace " ", "").Length -eq 0) {
            $Results.Status = "NotAFinding"
            $Results.Details = "Verified access this computer from the network right is only given to Administrators and Authenticated Users. See comments for details."
            $Results.Comments = ($right | Out-String)
        }
        else {
            $Results.Status = "Open"
            $Results.Details = "Access this computer from the network right contains more users/groups than Administrators and Authenticated Users; Please review! See comments for details."
            $Results.Comments = ($right | Out-String)
        }
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-26470 [$($Results.Status)]"

#Return results
return $Results
