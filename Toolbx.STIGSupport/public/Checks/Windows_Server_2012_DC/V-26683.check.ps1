<#
.SYNOPSIS
    This checks for compliancy on V-26683.

    PKI certificates associated with user accounts must be issued by the DoD PKI or an approved External Certificate Authority (ECA).

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-26683"

# Initial Variables
$Results = @{
    VulnID   = "V-26683"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
if ($PreCheck.hostType -eq "Domain Controller") {
    $fqdn = (Get-WmiObject -Class Win32_ComputerSystem).Domain
    $users = Get-ADUser -Properties SmartcardLogonRequired, LastLogonDate -Filter *
    $users = $users | Where-Object {$_.Enabled -eq $true}
    #Filter out accounts without PKI PNs
    $usersFilter = $users | Where-Object {$_.UserPrincipalName -notmatch $_.SamAccountName+("@$fqdn")}
    #Remove all accounts with valid seeming PKI PNs
    $bad = $usersFilter | Where-Object {$_.UserPrincipalName -notmatch "\d{9}@mil" -and $_.UserPrincipalName -notmatch "\d{10}\.\w{1}@mil" -and $_.SamAccountName -ne "Administrator" -and $_.SamAccountName -ne "xAdministrator" -and $_.SamAccountName -notmatch '\$'}
    if ($bad.Length -eq 0) {
        $Results.Status = "NotAFinding"
        $Results.Details = 'No accounts with @mil PN-PKI authentication deviate from expected naming.'
    }
    else {
        $Results.Status = "Open"
        $Results.Details = 'Found accounts with @mil PN-PKI authentication that deviate from expected naming; Please review! See comments for details.'
        $Results.Comments = $bad | Select-Object SamAccountName, DistinguishedName, UserPrincipalName, Enabled | Format-List | Out-String
    }
}
else {
    $Results.Status = "Not_Applicable"
    $Results.Details = "Check only applies to domain controllers."
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-26683 [$($Results.Status)]"

#Return results$bad.samuseraccount

return $Results
