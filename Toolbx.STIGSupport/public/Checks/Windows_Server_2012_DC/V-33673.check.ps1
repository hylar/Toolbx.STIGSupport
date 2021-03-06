<#
.SYNOPSIS
    This checks for compliancy on V-33673.

    Active Directory Group Policy objects must have proper access control permissions.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-33673"

# Initial Variables
$Results = @{
    VulnID   = "V-33673"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
if ($PreCheck.hostType -eq "Domain Controller") {
    Import-Module ActiveDirectory
    $gpos = (Get-Gpo -All)
    foreach ($gpo in $gpos) {
        $acl = (Get-Acl -Audit -Path ('AD:'+$gpo.Path))
        $rights = $acl.Access
        $owner = $acl.Owner -split '\\' | Select-Object -Last 1
        foreach ($right in $rights) {
            $name = $right.IdentityReference -split '\\' | Select-Object -Last 1
            if ($right.ActiveDirectoryRights -eq "GenericRead") {
                Write-Verbose "$name has Read-Only rights, skipping..."
                Continue
            }
            elseif ($name -eq "CREATOR OWNER") {
                #Replace CREATOR OWNER with actual owner account/group
                $name = $owner
            }
            $accounts = @()
            #If name in a group, get members; Otherwise treat as a single user account
            if (Get-AdGroup -Identity $name -ErrorAction SilentlyContinue) {
                $accounts = Get-AdGroupMember -Identity $name -Recursive | Where-Object  {$_.SID -notlike "S-1-5-21-*-500"}
            }
            else {
                $accounts = Get-AdUser $name
            }
            $fail = 0
            $failNames = @()
            foreach ($user in $accounts){
                #If user is not a domain admin (.adm) or is in a non-admin OU fail
                if ($user.SamAccountName -notlike "*.adm" -or !($user.distinguishedname -match "admin")) {
                    $fail = 1
                    $failNames += $user.SamAccountName
                }
            }
        }
        if ($fail -eq 1){
            $Results.Comments += ("`r`nGPO '"+$gpo.name+"' has members not verified as admins!")
            foreach ($failName in $failNames) {
                $Results.Comments += ("`t"+$failName)
            }
        }
    }
    if ($Results.Comments.Length -gt 0) {
        $Results.Status = "Open"
        $Results.Details = "Found accounts with GPO editing rights not verified as admins; Please review! See comments for details."
    }
    else {
        $Results.Status = "NotAFinding"
        $Results.Details = "Found no accounts with GPO editing rights that were not adminsistrators."
    }
}
else {
    $Results.Status = "Not_Applicable"
    $Results.Details = "Check only applies to Domain Controllers."
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-33673 [$($Results.Status)]"

#Return results
return $Results

<#OLD CHECK
if ($PSVersionTable.PSVersion.Major -lt 5) {
    $Results.Details = "PowerShell version too"
}
elseif ($PreCheck.hostType -eq "Domain Controller") {
    #Get GPOs into XML variable
    [xml]$xml = Get-GPOReport -All -ReportType XML
    #Drill down to GPO name
    $gpos = $xml.GPOS.GPO
    foreach ($gpo in $gpos) {
        #Get SDDL for SecurityDescriptor and process to plain-text
        $rights = (ConvertFrom-SddlString -Sddl $gpo.SecurityDescriptor.sddl."#text").DiscretionaryAcl
        foreach ($right in $rights) {
            $name = ($right -split ":" | Select-Object -First 1) -split '\\' | Select-Object -Last 1
            #Shunt for read-only rights
            if ($right -like "*AccessAllowed (CreateDirectories, GenericExecute, GenericRead, ReadAttributes, ReadPermissions, WriteExtendedAttributes)") {
                Write-Verbose "$name has Read-Only rights, skipping..."
                Continue
            }
            $accounts = @()
            #If name in a group, get members; Otherwise treat as a single user account
            if (Get-AdGroup -Identity $name -ErrorAction SilentlyContinue) {
                $accounts = Get-AdGroupMember -Identity $name -Recursive | Where-Object  {$_.SID -notlike "S-1-5-21-*-500"}
            }
            else {

                $accounts = $name
            }
            $fail = 0
            $failNames = @()
            foreach ($user in $accounts){
                #If user is not a domain admin (.adm) or is in a non-admin OU fail
                if ($user.SamAccountName -notlike "*.adm" -or !($user.distinguishedname -match "admin")) {
                    $fail = 1
                    $failNames += $user.SamAccountName
                }
            }
        }
        if ($fail -eq 1){
            $Results.Comments += ("`r`nGPO '"+$gpo.name+"' has members not verified as admins!")
            foreach ($failName in $failNames) {
                $Results.Comments += ("`t"+$failName)
            }
        }
    }
    if ($Results.Comments.Length -gt 0) {
        $Results.Status = "Open"
        $Results.Details = "Found accounts with GPO editing rights not verified as admins; Please review! See comments for details."
    }
    else {
        $Results.Status = "NotAFinding"
        $Results.Details = "Found no accounts with GPO editing rights that were not adminsistrators."
    }
}
else {
    $Results.Status = "Not_Applicable"
    $Results.Details = "Check only applies to Domain Controllers."
}
#>
