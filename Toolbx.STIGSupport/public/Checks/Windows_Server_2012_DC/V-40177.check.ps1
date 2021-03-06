<#
.SYNOPSIS
    This checks for compliancy on V-40177.

    Permissions for program file directories must conform to minimum requirements.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-40177"

# Initial Variables
$Results = @{
    VulnID   = "V-40177"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$folder = "C:\Program Files"
$folder86 = "C:\Program Files (x86)"
if (Test-Path $folder) {
    $access = (Get-Acl -Path $folder).Access
    $filter=(
        $access |
        Where-Object {$_.IdentityReference -notlike "NT SERVICE\TrustedInstaller" -or $_.FileSystemRights -ne "FullControl"  -or $_.InheritanceFlags -ne "None" -or $_.PropagationFlags -ne "None"} |
        Where-Object {$_.IdentityReference -notlike "NT SERVICE\TrustedInstaller" -or $_.InheritanceFlags -ne "ContainerInherit" -or $_.PropagationFlags -ne "InheritOnly" -or $_.FileSystemRights -ne "268435456"} |
        Where-Object {$_.IdentityReference -notlike "NT AUTHORITY\SYSTEM" -or $_.FileSystemRights -ne "Modify, Synchronize" -or $_.InheritanceFlags -ne "None" -or $_.PropagationFlags -ne "None"} |
        Where-Object {$_.IdentityReference -notlike "NT AUTHORITY\SYSTEM" -or $_.InheritanceFlags -ne "ContainerInherit, ObjectInherit" -or $_.PropagationFlags -ne "InheritOnly" -or $_.FileSystemRights -ne "268435456"} |
        Where-Object {$_.IdentityReference -notlike "BUILTIN\Administrators" -or $_.FileSystemRights -ne "Modify, Synchronize" -or $_.InheritanceFlags -ne "None" -or $_.PropagationFlags -ne "None"} |
        Where-Object {$_.IdentityReference -notlike "BUILTIN\Administrators" -or $_.InheritanceFlags -ne "ContainerInherit, ObjectInherit" -or $_.PropagationFlags -ne "InheritOnly" -or $_.FileSystemRights -ne "268435456"} |
        Where-Object {$_.IdentityReference -notlike "BUILTIN\Users" -or $_.FileSystemRights -ne "ReadAndExecute, Synchronize" -or $_.InheritanceFlags -ne "None" -or $_.PropagationFlags -ne "None"} |
        Where-Object {$_.IdentityReference -notlike "BUILTIN\Users" -or $_.InheritanceFlags -ne "ContainerInherit, ObjectInherit" -or $_.PropagationFlags -ne "InheritOnly" -or $_.FileSystemRights -ne "-1610612736"} |
        Where-Object {$_.IdentityReference -notlike "CREATOR OWNER" -or $_.InheritanceFlags -ne "ContainerInherit, ObjectInherit" -or $_.PropagationFlags -ne "InheritOnly" -or $_.FileSystemRights -ne "268435456"} |
        Where-Object {$_.IdentityReference -notlike "APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES" -or $_.FileSystemRights -ne "ReadAndExecute, Synchronize"} |
        Where-Object {$_.IdentityReference -notlike "APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES" -or $_.InheritanceFlags -ne "ContainerInherit, ObjectInherit" -or $_.PropagationFlags -ne "InheritOnly" -or $_.FileSystemRights -ne "-1610612736"}
    )
}
else {
    $Results.Status = "Open"
    $Results.Details = "The path '$folder'cannot be found!"
}
if (Test-Path $folder86) {
    $access86 = (Get-Acl -Path $folder86).Access
    $filter86=(
        $access86 |
        Where-Object {$_.IdentityReference -notlike "NT SERVICE\TrustedInstaller" -or $_.FileSystemRights -ne "FullControl"  -or $_.InheritanceFlags -ne "None" -or $_.PropagationFlags -ne "None"} |
        Where-Object {$_.IdentityReference -notlike "NT SERVICE\TrustedInstaller" -or $_.InheritanceFlags -ne "ContainerInherit" -or $_.PropagationFlags -ne "InheritOnly" -or $_.FileSystemRights -ne "268435456"} |
        Where-Object {$_.IdentityReference -notlike "NT AUTHORITY\SYSTEM" -or $_.FileSystemRights -ne "Modify, Synchronize" -or $_.InheritanceFlags -ne "None" -or $_.PropagationFlags -ne "None"} |
        Where-Object {$_.IdentityReference -notlike "NT AUTHORITY\SYSTEM" -or $_.InheritanceFlags -ne "ContainerInherit, ObjectInherit" -or $_.PropagationFlags -ne "InheritOnly" -or $_.FileSystemRights -ne "268435456"} |
        Where-Object {$_.IdentityReference -notlike "BUILTIN\Administrators" -or $_.FileSystemRights -ne "Modify, Synchronize" -or $_.InheritanceFlags -ne "None" -or $_.PropagationFlags -ne "None"} |
        Where-Object {$_.IdentityReference -notlike "BUILTIN\Administrators" -or $_.InheritanceFlags -ne "ContainerInherit, ObjectInherit" -or $_.PropagationFlags -ne "InheritOnly" -or $_.FileSystemRights -ne "268435456"} |
        Where-Object {$_.IdentityReference -notlike "BUILTIN\Users" -or $_.FileSystemRights -ne "ReadAndExecute, Synchronize" -or $_.InheritanceFlags -ne "None" -or $_.PropagationFlags -ne "None"} |
        Where-Object {$_.IdentityReference -notlike "BUILTIN\Users" -or $_.InheritanceFlags -ne "ContainerInherit, ObjectInherit" -or $_.PropagationFlags -ne "InheritOnly" -or $_.FileSystemRights -ne "-1610612736"} |
        Where-Object {$_.IdentityReference -notlike "CREATOR OWNER" -or $_.InheritanceFlags -ne "ContainerInherit, ObjectInherit" -or $_.PropagationFlags -ne "InheritOnly" -or $_.FileSystemRights -ne "268435456"} |
        Where-Object {$_.IdentityReference -notlike "APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES" -or $_.FileSystemRights -ne "ReadAndExecute, Synchronize"} |
        Where-Object {$_.IdentityReference -notlike "APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES" -or $_.InheritanceFlags -ne "ContainerInherit, ObjectInherit" -or $_.PropagationFlags -ne "InheritOnly" -or $_.FileSystemRights -ne "-1610612736"}
    )
}
else {
    $Results.Status = "Open"
    $Results.Details = $Results.Details+"`r`nThe path '$folder86'cannot be found!"
}

if ($filter.Length -eq 0 -and (Test-Path $folder)) {
    $Results.Details = "Registry permissions for '$folder' indicate appropriate permissions. See comments for details."
    $Results.Comments = "$folder`r`n"+($access | Select-Object IdentityReference,RegistryRights,InheritanceFlags | Format-List | Out-String)
}
elseif ($Results.Status -ne "Open") {
    $Results.Status = "Open"
    $Results.Details = "Registry permissions for '$folder' have unexpected permissions, pelase review! See comments for details."
    $Results.Comments = "$folder`r`n"+($access | Select-Object IdentityReference,RegistryRights,InheritanceFlags | Format-List | Out-String)
}

if ($filter86.Length -eq 0 -and (Test-Path $folder86)) {
     $Results.Details = "Registry permissions for '$folder86' indicate appropriate permissions. See comments for details."
     $Results.Comments = $Results.Comments+"`r`n$folder`r`n"+($access | Select-Object IdentityReference,RegistryRights,InheritanceFlags | Format-List | Out-String)
}
elseif ($Results.Status -ne "Open") {
    $Results.Status = "Open"
    $Results.Details = "Registry permissions for '$folder86' have unexpected permissions, pelase review! See comments for details."
    $Results.Comments = $Results.Comments+"`r`n$folder`r`n"+($access | Select-Object IdentityReference,RegistryRights,InheritanceFlags | Format-List | Out-String)
}
if ($Results.Status -ne "Open") {
    $Results.Status = "NotAFinding"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-40177 [$($Results.Status)]"

#Return results
return $Results
