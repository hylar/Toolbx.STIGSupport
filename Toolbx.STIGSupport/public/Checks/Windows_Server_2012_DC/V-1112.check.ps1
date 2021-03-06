<#
.SYNOPSIS
    This checks for compliancy on V-1112.

    Outdated or unused accounts must be removed from the system or disabled.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-1112"

# Initial Variables
$Results = @{
    VulnID   = "V-1112"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
if ($PreCheck.hostType -ne "Domain Controller"){
    #Member server/non-domain check
    $accounts = Get-LocalUser | Where-Object {$_.Enabled -eq $true -and $_.sid.Value -notlike "*-500" -and $_.sid.Value -notlike "*-501"}
    $fail = 0
    $failNames = @()
    foreach ($account in $accounts) {
        [datetime]$lastLogon = $account.LastLogon
        [datetime]$date = Get-Date
        if ($lastLogon -ge $date.AddDays(-35)) {
            #Good
        }        else {
            $fail = 1
            $failNames += ("Account '"+$account.Name+"' with SID '"+$account.sid.Value+"'has not logged on since $lastLogon!")
        }
    }
    if ($fail -eq 0){
        $Results.Status = "NotAFinding"
        $Results.Details = "Found no accounts on machine that are enabled and have not been logged into withn 35 days. See comments for details."
        $Results.Comments = "-=All Relevant Accounts Found=-"
        $Results.Comments += ($accounts | Select-Object Name,LastLogon | Format-List | Out-String)
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Found accounts on machine that are enabled and have not been logged into withn 35 days; Please review! See comments for details."
        $Results.Comments = "-=Failed Accounts=-`r`n"
        $Results.Comments += $failNames | Format-List | Out-String
        $Results.Comments += "`r`n-=All Accounts Found=-"
        $Results.Comments += ($accounts | Select-Object Name,LastLogon | Format-List | Out-String)
    }
}
else {
    #Domain controllor check using -AccountInactive to add pad days
    $accounts = Search-ADAccount -AccountInactive -UsersOnly -TimeSpan 35.00:00:00 | Where-Object {$_.Enabled -eq $true -and $_.SID -notlike "*-500" -and $_.SID -notlike "*-501"}
    #Filter to remove accouns younger than 35 days
    $failNames = @()
    [datetime]$date=Get-Date
    foreach ($account in $accounts) {
        $temp=Get-AdUser $account.SamAccountName -Properties SamAccountName, LastLogonDate, WhenCreated, DistinguishedName, LastLogonTimeStamp
        #Check if account is younger than 35 days
        if ($temp.whencreated -lt $date.AddDays(-35)) {
            $failNames += $temp
        }
    }
    if ($failNames.Count -eq 0){
        $Results.Status = "NotAFinding"
        $Results.Details = "Found no accounts in Active Directory that are enabled and have not been logged into withn 35 days."
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Found accounts in Active Directory that are enabled and have not been logged into withn 35 days, please review! See comments for details."
        $Results.Comments = ($failNames | Select-Object  SamAccountName, LastLogonDate, WhenCreated, DistinguishedName, LastLogonTimeStamp | Format-List | Out-String)
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-1112 [$($Results.Status)]"

#Return results
return $Results
