<#
.SYNOPSIS
    This checks for compliancy on V-36662.

    Windows 2012/2012 R2 manually managed application account passwords must be changed at least annually or when a system administrator with knowledge of the password leaves the organization.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-36662"

# Initial Variables
$Results = @{
    VulnID   = "V-36662"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
if ( $PreCheck.hostType -ne "Domain Controller") {
    #Member server and non-domain scan of local accounts
    $accounts = Get-CimInstance -Class Win32_Useraccount -Filter "Disabled=False and LocalAccount=True"
    foreach ($account in $accounts) {
        Net User ($account.Name) | Find /i "Password Last Set"
        [DateTime]$date = ((Net User ($account.Name) | Find /i "Password Last Set") -split " " | Select-Object -Last 3) -join " "
        if ($date -lt (Get-Date).AddYears(-1)) {
            $Results.Status = "Open"
            $Results.Comments = ($Results.Comments+"`r`nLocal account '"+$account.Name+"' has a password that was last set "+$date+"!")
        }
        else {
            $Results.Comments = ($Results.Comments+"`r`nLocal account '"+$account.Name+"' has a password that was last set "+$date+".")
        }
    }
    if ($Results.Status -eq "Open") {
        $Results.Details = "Found one or more local accounts with a password age greater than one year! See comments for details."
    }
    else {
        $Result.Status = "NotAFinding"
        $Results.Details = "All enabled local accounts have passwords last set within a year. See comments for details."

    }
}
else {
    #Domain server AD scan
    $accounts = (Get-ADUser -Filter * -Properties SmartcardLogonRequired, PasswordLastSet) | Where-Object {$_.SmartcardLogonRequired -eq $false -and $_.Enabled -eq $true}
    foreach ($account in $accounts) {
        [DateTime]$date = $account.PasswordLastSet
        if ($date -lt (Get-Date).AddYears(-1)) {
            $Results.Status = "Open"
            $Results.Comments = ($Results.Comments+"`r`nAccount '"+$account.Name+"' has a password that was last set "+$date+"!")
        }
        elseif (!$date) {
            $Results.Status = "Open"
            $Results.Comments = ($Results.Comments+"`r`nAccount '"+$account.Name+"' last password date is NULL!")
        }
        #else {$Results.Comments = ($Results.Comments+"`r`nAccount '"+$account.Name+"' has a password that was last set "+$date+".")}
    }
    if ($Results.Status -eq "Open") {
        $Results.Details = "Found one or more accounts with a password age greater than one year! See comments for details."
    }
    else {
        $Result.Status = "NotAFinding"
        $Results.Details = "All enabled accounts have passwords last set within a year. See comments for details."
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-36662 [$($Results.Status)]"

#Return results
return $Results
