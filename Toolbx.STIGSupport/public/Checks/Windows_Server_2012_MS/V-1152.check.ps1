<#
.SYNOPSIS
    This checks for compliancy on V-1152.

    Anonymous access to the registry must be restricted.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-1152"

# Initial Variables
$Results = @{
    VulnID   = "V-1152"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
[string]$keyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\"
if (!$keyPath) {
    $Results.Status = "Open"
    $Results.Details = "Registry value at $keyPath was not found!"
}
else{
    $access=(Get-Acl $keyPath).Access
    $filter=(
        $access |
        Where-Object {$_.IdentityReference -ne "BUILTIN\Administrators" -or $_.RegistryRights -ne "FullControl"} |
        Where-Object {$_.IdentityReference -ne "BUILTIN\Administrators" -or $_.InheritanceFlags -ne "ContainerInherit"} |
        Where-Object {$_.IdentityReference -ne "BUILTIN\Backup Operators" -or $_.RegistryRights -ne "ReadKey"} |
        Where-Object {$_.IdentityReference -ne "NT AUTHORITY\LOCAL SERVICE" -or $_.RegistryRights -ne "ReadKey"} |
        Where-Object {$_.IdentityReference -ne "NT AUTHORITY\LOCAL SERVICE" -or $_.InheritanceFlags -ne "ContainerInherit"}
    )
    if ($filter.Length -eq 0) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Registry permissions at $keyPath indicate appropriate permissions. See comments for details."
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Registry permissions at $keyPath have unexpected permissions, pelase review! See comments for details."
    }
    $Results.Comments = $access | Select-Object IdentityReference,RegistryRights,InheritanceFlags | Format-List | Out-String
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-1152 [$($Results.Status)]"

#Return results
return $Results
