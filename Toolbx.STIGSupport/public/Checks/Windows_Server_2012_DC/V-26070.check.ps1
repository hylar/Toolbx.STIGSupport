<#
.SYNOPSIS
    This checks for compliancy on V-26070.

    Standard user accounts must only have Read permissions to the Winlogon registry key.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-26070"

# Initial Variables
$Results = @{
    VulnID   = "V-26070"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
[string]$keyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\"
if (!$keyPath) {
    $Results.Status = "Open"
    $Results.Details = "Registry value at $keyPath was not found!"
}
else{
    $access=(Get-Acl $keyPath).Access
    $filter=(
        $access |
        Where-Object {$_.IdentityReference -ne "BUILTIN\Administrators" -or $_.RegistryRights -ne "FullControl" -or $_.InheritanceFlags -ne "None"} |
        Where-Object {$_.IdentityReference -ne "BUILTIN\Administrators" -or $_.InheritanceFlags -ne "ContainerInherit"} |
        Where-Object {$_.IdentityReference -ne "BUILTIN\Backup Operators" -or $_.RegistryRights -ne "ReadKey" -or $_.InheritanceFlags -ne "None"} |
        Where-Object {$_.IdentityReference -ne "BUILTIN\Backup Operators" -or $_.InheritanceFlags -ne "ContainerInherit"} |
        Where-Object {$_.IdentityReference -ne "BUILTIN\Users" -or $_.RegistryRights -ne "ReadKey" -or $_.InheritanceFlags -ne "None"} |
        Where-Object {$_.IdentityReference -ne "BUILTIN\Users" -or $_.InheritanceFlags -ne "ContainerInherit"} |
        Where-Object {$_.IdentityReference -ne "NT AUTHORITY\SYSTEM" -or $_.RegistryRights -ne "FullControl" -or $_.InheritanceFlags -ne "None"} |
        Where-Object {$_.IdentityReference -ne "NT AUTHORITY\SYSTEM" -or $_.InheritanceFlags -ne "ContainerInherit"} |
        Where-Object {$_.IdentityReference -ne "NT SERVICE\TrustedInstaller" -or $_.RegistryRights -ne "FullControl" -or $_.InheritanceFlags -ne "None"} |
        Where-Object {$_.IdentityReference -ne "NT SERVICE\TrustedInstaller" -or $_.InheritanceFlags -ne "ContainerInherit"} |
        Where-Object {$_.IdentityReference -ne "APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES" -or $_.RegistryRights -ne "ReadKey" -or $_.InheritanceFlags -ne "None"} |
        Where-Object {$_.IdentityReference -ne "APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES" -or $_.InheritanceFlags -ne "ContainerInherit"}
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

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-26070 [$($Results.Status)]"

#Return results
return $Results
