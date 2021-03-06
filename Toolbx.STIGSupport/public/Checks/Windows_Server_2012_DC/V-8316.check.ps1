<#
.SYNOPSIS
    This checks for compliancy on V-8316.

    Active Directory data files must have proper access control permissions.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-8316"

# Initial Variables
$Results = @{
    VulnID   = "V-8316"
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
    $path = $key.$valueName
    $path2 = $key2.$valueName2
    $icacls = icacls $path\*.*
    $icacls2 = icacls $path2

    function TestDirectoryServicesDatabaseRights {
        param(
            [Parameter(Mandatory=$true,Position=0)]$path
        )
        [int]$fail = 0
        foreach ($line in $path) {
            if (
                $line -like "*NT AUTHORITY\SYSTEM:(I)(F)" -or
                $line -like "*BUILTIN\Administrators:(I)(F)" -or
                $line -eq "" -or
                $line -like "*; Failed processing 0 files"
            ) {}
            else {
                [int]$fail = 1
            }
        }
        Return $fail
    }

    if ((TestDirectoryServicesDatabaseRights -path $path) -eq 0) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Permissions for files in $path are as expected. See comments for details."
        $Results.Comments = $icacls | Out-String

    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Permissions for files in $path are NOT as expected; Please review! See comments for details."
        $Results.Comments = $icacls | Out-String
    }

    if ((TestDirectoryServicesDatabaseRights -path $path) -eq 0) {
        $Results.Details = $Results.Details + "`r`nPermissions for files in $path2 are as expected. See comments for details."
        $Results.Comments = $Results.Comments + "`r`n" + ($icacls2 | Out-String)

    }
    else {
        $Results.Status = "Open"
        $Results.Details = $Results.Details + "`r`nPermissions for files in $path2 are NOT as expected; Please review! See comments for details."
        $Results.Comments = $Results.Comments + "`r`n" + ($icacls2 | Out-String)
    }
}
else {
    $Results.Status = "Not_Applicable"
    $Results.Details = "Check is only valid for Domain Controllers."
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-8316 [$($Results.Status)]"

#Return results
return $Results
