<#
.SYNOPSIS
    This checks for compliancy on V-6840.

    Windows 2012/2012 R2 passwords must be configured to expire.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-6840"

# Initial Variables
$Results = @{
    VulnID   = "V-6840"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
if ( $PreCheck.hostType -ne "Domain Controller") {
    $accounts = Get-CimInstance -Class Win32_Useraccount -Filter "PasswordExpires=False and LocalAccount=True and Disabled=False" | FT Name,PasswordExpires,Disabled,LocalAccount
    if ($account.Length -eq 0){
        $Results.Status = "NotAFinding"
        $Results.Details = "No enabled local accounts with passwords set to never expire were found. See comments for details."
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Found accounts that need review! See comments for details."
        $Results.Comments = $accounts | Format-List | Out-String
    }
}
else {
    #CHECK WIP need testing on Domain Controller
    $accounts = Search-ADAccount -PasswordNeverExpires -UsersOnly | Where (PasswordNeverExpires -eq True -and Enabled -eq True) | FT Name, PasswordNeverExpires, Enabled
    if ($account.Length -eq 0){
        $Results.Status = "NotAFinding"
        $Results.Details = "No enabled accounts with passwords set to never expire were found in Active Directory. See comments for details."
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Found accounts that need review! See comments for details."
        $Results.Comments = $accounts | Format-List | Out-String
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-6840 [$($Results.Status)]"

#Return results
return $Results
