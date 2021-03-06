<#
.SYNOPSIS
    This checks for compliancy on V-39331.

    The Active Directory SYSVOL directory must have the proper access control permissions.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-39331"

# Initial Variables
$Results = @{
    VulnID   = "V-39331"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
if ($PreCheck.hostType -eq "Domain Controller") {
    Import-Module ActiveDirectory
    $acl = (Get-Acl -Audit -Path ("$env:SystemRoot\SYSVOL\sysvol"))
    $rights = $acl.Access
    $fail = 0
    foreach ($right in $rights) {
        $name = $right.IdentityReference

        #Sort out read-only/authenticated users/SYSTEM and fix CREATOR OWNER
        if ($right.FileSystemRights -eq "ReadAndExecute, Synchronize" -or $right.FileSystemRights -eq -1610612736) {
            #Ignore entries with read-only rights
            Write-Verbose "$name has Read-Only rights, skipping analysis."
            Continue
        }
        elseif ($name -eq "NT AUTHORITY\Authenticated Users") {
            #Authenicated Users should not have rights above Read-Only
            Write-Verbose "$name has more than Read-Only rights! Failure noted!"
            $fail = 1
            $Results.Comments += "`r`nFound '$user' has elevated rights, but is not an Adminsitrator!"
        }
        elseif ($name -eq "NT AUTHORITY\SYSTEM") {
            #SYSTEM is an admin
            Write-Verbose "$name is an administrator, skipping analysis."
            Continue
        }
        elseif ($name -eq "CREATOR OWNER") {
            #Replace CREATOR OWNER with actual owner account/group
            $name = $acl.Owner
        }
        $accounts = Get-LocalGroupMember -Name ($name -split '\\' | Select-Object -Last 1)
        $localUsers = @()
        $adGroups = @()
        $adUsers = @()
        $localGroups = @()
        #Sort initial users and groups into appropriate arrays
        $localUsers += ($accounts | Where-Object {($_.Name -like "BUILTIN\*" -or $_.Name -like "$env:COMPUTERNAME\*") -and $_.ObjectClass -eq "User"}).Name
        $adGroups += ($accounts | Where-Object {$_.Name -notlike "BUILTIN\*" -and $_.Name -notlike "$env:COMPUTERNAME\*" -and $_.ObjectClass -eq "Group"}).Name
        $adUsers += ($accounts | Where-Object {$_.Name -notlike "BUILTIN\*" -and $_.Name -notlike "$env:COMPUTERNAME\*" -and $_.ObjectClass -eq "User"}).Name
        $localGroups = $accounts | Where-Object {($_.Name -like "BUILTIN\*" -or $_.Name -like "$env:COMPUTERNAME\*") -and $_.ObjectClass -eq "Group"}
        #Enumerate through local admins, adding local users found to array
        $localAdmins = @()
        $localAdmins += Get-LocalGroupMember -Name "Administrators" | Where-Object {($_.Name -like "BUILTIN\*" -or $_.Name -like "$env:COMPUTERNAME\*") -and $_.ObjectClass -eq "User"}
        $localAdminGroups = Get-LocalGroupMember -Name "Administrators" | Where-Object {($_.Name -like "BUILTIN\*" -or $_.Name -like "$env:COMPUTERNAME\*") -and $_.ObjectClass -eq "Group"}
        do {
            $temp = $localAdminGroups
            foreach ($t in $temp) {
                $members = Get-LocalGroupMember -Name ($t.Name -split '\\' | Select-Object -Last 1)
                $localAdminGroups = $members | Where-Object {($_.Name -like "BUILTIN\*" -or $_.Name -like "$env:COMPUTERNAME\*") -and $_.ObjectClass -eq "Group"}
                $localAdmins += ($members | Where-Object {($_.Name -like "BUILTIN\*" -or $_.Name -like "$env:COMPUTERNAME\*") -and $_.ObjectClass -eq "User"}).Name
            }
        } until ($localAdminGroups.Count -eq 0)
        #Enumerate through all local groups, adding everything found to arrays until no local groups are left.
        do {
            $temp = $localGroups
            foreach ($t in $temp) {
                $members = Get-LocalGroupMember -Name ($t.Name -split '\\' | Select-Object -Last 1)
                $localGroups = $members | Where-Object {($_.Name -like "BUILTIN\*" -or $_.Name -like "$env:COMPUTERNAME\*") -and $_.ObjectClass -eq "Group"}
                $localUsers += ($members | Where-Object {($_.Name -like "BUILTIN\*" -or $_.Name -like "$env:COMPUTERNAME\*") -and $_.ObjectClass -eq "User"}).Name
                $adGroups += ($members | Where-Object {$_.Name -notlike "BUILTIN\*" -and $_.Name -notlike "$env:COMPUTERNAME\*" -and $_.ObjectClass -eq "Group"}).Name
                $adUsers += ($members | Where-Object {$_.Name -notlike "BUILTIN\*" -and $_.Name -notlike "$env:COMPUTERNAME\*" -and $_.ObjectClass -eq "User"}).Name
            }
        } until ($localGroups.Count -eq 0)
        #Verify all local users found are members of the Administrators group
        foreach ($user in $localUsers) {
            if ($localAdmins.Name -match [regex]::escape($user)) {
                #Good
            }
            else {
                $fail = 1
                $Results.Comments += "`r`nFound local user '$user' with elevated rights, but is not member of Adminsitrators!"
            }
        }
        #Pull AD info for all AD users and members of AD groups (recusively) and add to final array (ignore default admin).
        $adUsersFinal = @()
        if ($adUsers) {
            foreach ($user in $adUsers) {
                $adUsersFinal += Get-AdUser -Identity ($user -split '\\' | Select-Object -Last 1)
            }
        }
        if ($adGroups) {
            foreach ($group in $adGroups) {
                $adUsersFinal += Get-AdGroupMember -Identity ($group -split '\\' | Select-Object -Last 1) -Recursive | Where-Object  {$_.SID -notlike "S-1-5-21-*-500"}
            }
        }
        #Check $adUsersFinal against hard-coded patterns
        foreach ($user in $adUsersFinal) {
            #Account must be .adm or .admin
            if ($user.SamAccountName -notlike "*.adm" -and $user.SamAccountName -notlike "*.admin") {
                $fail = 1
                $Results.Comments += "Active Directory user '"+$user.SamAccountName+"' does not end with .adm or .admin!"
            }
            #Account must be in an admin OU
            if (!($user.distinguishedname -match "admin")) {
                $fail = 1
                $Results.Comments += "Active Directory user '"+$user.SamAccountName+"' is not in an admin organizational unit!"
            }
        }
    }
    if ($fail -eq 0) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Scanned local and AD accounts, found no non-privileged accounts with access to SYSVOL."
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Found accounts with unexpected rights to SYSVOL; Please review! See comments for details."
    }
}
else {
    $Results.Status = "Not_Applicable"
    $Results.Details = "Check only applies to Domain Controllers."
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-39331 [$($Results.Status)]"

#Return results
return $Results
