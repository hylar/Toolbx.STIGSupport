<#
.SYNOPSIS
    This checks for compliancy on V-1127.

    Only administrators responsible for the member server must have Administrator rights on the system.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-1127"

# Initial Variables
$Results = @{
    VulnID   = "V-1127"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$admins=Get-LocalGroupMember -Name Administrators

<#
$localAdmin=($precheck.secEdit -match "NewAdministratorName" -split "= " | Select-Object -Last 1) -replace '"',''

$filteredAdmins = $admins | Where-Object {$_.Name -ne "$env:COMPUTERNAME\$localAdmin"}
$filteredAdmins = $filteredAdmins | Where-Object {$_.ObjectClass -ne "Group" -or $_.Name -ne ($PreCheck.domain+"\Domain Member Server Admins")}

#>
if ($PreCheck.hostType -eq "Domain Controller") {
    $accounts = Get-LocalGroupMember -Name "Administrators" | Where-Object {$_.sid.value -notlike "*-500"}
    $fail = 0
    #$accounts = Get-LocalGroupMember -Name ($name -split '\\' | Select-Object -Last 1)
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
    $localAdmins += Get-LocalGroupMember -Name "Administrators" | Where-Object {($_.Name -like "BUILTIN\*" -or $_.Name -like "$env:COMPUTERNAME\*") -and $_.ObjectClass -eq "User" -and $_.sid.value -notlike "*-500"}
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
    if ($fail -eq 0 -and !($localAdmins)) {
        $Results.Status = "NotAFinding"
        $Results.Details = "Scanned local and AD accounts, found no non-privileged accounts with access to SYSVOL. No local admins exist beyond default."
    }
    elseif ($fail -eq 0) {
        $Results.Status = "Not_Reviewed"
        $Results.Details = "Scanned local and AD accounts, found no non-privileged accounts with access to SYSVOL. Found local admins beyond default; Please review! See comments for details."
        $Results.Comments += "-=Suspect Local Admins=-"
        $Results.Comments += $localAdmins | Select Name,SID,ObjectClass | Format-List | Out-String
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

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-1127 [$($Results.Status)]"

#Return results
return $Results
