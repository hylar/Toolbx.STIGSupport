<#
.SYNOPSIS
    This checks for compliancy on V-7002.

    Windows 2012/2012 R2 accounts must be configured to require passwords.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-7002"

# Initial Variables
$Results = @{
    VulnID   = "V-7002"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
if ( $PreCheck.hostType -ne "Domain Controller") {
    $accounts = Get-CimInstance -Class Win32_Useraccount -Filter "PasswordRequired=False and LocalAccount=True and Disabled=False" | FT Name,PasswordExpires,Disabled,LocalAccount
    if ($accounts.Length -eq 0){
        $Results.Status = "NotAFinding"
        $Results.Details = "All enabled local accounts require passwords. See comments for details."
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Found accounts that need review! See comments for details."
    }
    $Results.Comments = $accounts | Format-List | Out-String
}
else {
    #Domain Controller
    $accounts = Get-ADUser -Filter * -Properties PasswordNotRequired | Where-Object ($_PasswordNotRequired -eq $True -and $_.Enabled -eq $True) | FT Name, PasswordNotRequired, Enabled
    if ($account.Length -eq 0){
        $Results.Status = "NotAFinding"
        $Results.Details = "All enabled accounts found in Active Directory are set to require passwords."
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Found accounts that need review! See comments for details."
        $Results.Comments = $accounts | Select-Object SamAccountName, Enabled, PasswordNotRequired, DistinguishedName  | Format-List | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-7002 [$($Results.Status)]"

#Return results
return $Results
