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
    $accounts=@()
    ([ADSI]('WinNT://{0}' -f $env:COMPUTERNAME)).Children | Where { $_.SchemaClassName -eq 'user' } | ForEach {
        $user = ([ADSI]$_.Path)
        $lastLogin = $user.Properties.LastLogin.Value
        $enabled = ($user.Properties.UserFlags.Value -band 0x2) -ne 0x2
        if ($lastLogin -eq $null) {
            $lastLogin = (Get-Date).AddYears(-2000)
        }
        if($lastLogin -lt (Get-Date).AddDays(-35) -and $enabled -eq $true){
            $temp=New-Object psobject
            $temp | Add-Member NoteProperty Account $user.Path
            $temp | Add-Member NoteProperty LastLogin $lastLogin
            $temp | Add-Member NoteProperty Enabled $enabled
            $accounts += $temp
        }
    }
    if ($accounts.Count -eq 0){
        $Results.Status = "NotAFinding"
        $Results.Details = "Found no accounts on machine that are enabled and have not been logged into withn 35 days."
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Found accounts on machine that are enabled and have not been logged into withn 35 days, please review! See comments for details."
        $Results.Comments = ($accounts | Format-List | Out-String)
    }
}
else {
    #Domain controllor check
    $accounts=Search-ADAccount -AccountInactive -UsersOnly -TimeSpan 35.00:00:00 | Where-Object {$_.Enabled -eq $true -and $_.SID -notlike "*-500" -and $_.SID -notlike "*-501"}
    if ($accounts.Count -eq 0){
        $Results.Status = "NotAFinding"
        $Results.Details = "Found no accounts in Active Directory that are enabled and have not been logged into withn 35 days."
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Found accounts in Active Directory that are enabled and have not been logged into withn 35 days, please review! See comments for details."
        $Results.Comments = ($accounts | Format-List | Out-String)
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-1112 [$($Results.Status)]"

#Return results
return $Results
