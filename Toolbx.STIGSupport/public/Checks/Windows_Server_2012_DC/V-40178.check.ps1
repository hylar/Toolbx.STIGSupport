<#
.SYNOPSIS
    This checks for compliancy on V-40178.

    Permissions for system drive root directory (usually C:\) must conform to minimum requirements.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-40178"

# Initial Variables
$Results = @{
    VulnID   = "V-40178"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$folder = "C:"
<#Positive filter testing
$baseline = @()
$baseline += New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
$baseline += New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
$baseline += New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Users", "ReadAndExecute, Synchronize", "ContainerInherit, ObjectInherit", "None", "Allow")
$baseline += New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
$baseline += New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
#>
if (Test-Path $folder) {
    $access = (Get-Acl -Path $folder).Access
    $filter=(
        $access |
        Where-Object {$_.IdentityReference -notlike "NT AUTHORITY\SYSTEM" -or $_.FileSystemRights -ne "FullControl" -or $_.InheritanceFlags -ne "ContainerInherit, ObjectInherit"  -or $_.PropagationFlags -ne "None"} |
        Where-Object {$_.IdentityReference -notlike "BUILTIN\Administrators" -or $_.FileSystemRights -ne "FullControl" -or $_.InheritanceFlags -ne "ContainerInherit, ObjectInherit"  -or $_.PropagationFlags -ne "None"} |
        Where-Object {$_.IdentityReference -notlike "BUILTIN\Administrators" -or $_.InheritanceFlags -ne "ContainerInherit, ObjectInherit" -or $_.PropagationFlags -ne "InheritOnly" -or $_.FileSystemRights -ne "268435456"} |
        Where-Object {$_.IdentityReference -notlike "BUILTIN\Users" -or $_.FileSystemRights -ne "ReadAndExecute, Synchronize" -or $_.InheritanceFlags -ne "ContainerInherit, ObjectInherit"  -or $_.PropagationFlags -ne "None"} |
        Where-Object {$_.IdentityReference -notlike "BUILTIN\Users" -or $_.FileSystemRights -ne "AppendData" -or $_.InheritanceFlags -ne "ContainerInherit"  -or $_.PropagationFlags -ne "None"} |
        Where-Object {$_.IdentityReference -notlike "BUILTIN\Users" -or $_.FileSystemRights -ne "CreateFiles" -or $_.InheritanceFlags -ne "ContainerInherit"  -or $_.PropagationFlags -ne "InheritOnly"} |
        Where-Object {$_.IdentityReference -notlike "CREATOR OWNER" -or $_.InheritanceFlags -ne "ContainerInherit, ObjectInherit" -or $_.PropagationFlags -ne "InheritOnly" -or $_.FileSystemRights -ne "268435456"}
    )
}
else {
    $Results.Status = "Open"
    $Results.Details = "The path '$folder'cannot be found!"
}

if ($filter.Length -eq 0 -and (Test-Path $folder)) {
    $Results.Details = "Registry permissions for '$folder' indicate appropriate permissions. See comments for details."
    $Results.Comments = "$folder`r`n"+($access | Select-Object IdentityReference,RegistryRights,InheritanceFlags | Format-List | Out-String)
}
elseif ($Results.Status -ne "Open") {
    $Results.Status = "Open"
    $Results.Details = "Registry permissions for '$folder' have unexpected permissions, pelase review! See comments for details."
    $Results.Comments = "$folder`r`n"+($Filter | Select-Object IdentityReference,RegistryRights,InheritanceFlags | Format-List | Out-String)
}
if ($Results.Status -ne "Open") {
    $Results.Status = "NotAFinding"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-40178 [$($Results.Status)]"

#Return results
return $Results
