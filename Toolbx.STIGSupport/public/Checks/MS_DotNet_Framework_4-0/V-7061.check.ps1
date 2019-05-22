<#
.SYNOPSIS
    This checks for compliancy on V-7061.

    The Trust Providers Software Publishing State must be set to 0x23C00.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)] Checking - V-7061"

# Initial Variables
$Results = @{
    VulnID   = "V-7061"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

$Found = $false;

#Perform necessary check

# Map HKEY_USERS
New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS -ErrorAction SilentlyContinue | Out-Null

Get-ChildItem "HKU:\" -ErrorAction SilentlyContinue | ForEach-Object {

    #TODO: Need to determine if user profiles with _classes should be checked since that key wont exist.

    Write-Debug "[$($MyInvocation.MyCommand)] Checking $($_.PSChildName)"

    if (Test-Path ("HKU:\" + $_.PSChildName + "\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing\")) {

        $reg = Get-ItemProperty -Path ("HKU:\" + $usr.PSChildName + "\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing\") -Name "State" -ErrorAction SilentlyContinue

        if ($reg -eq $null) {
            $Found = $true
            $Results.Comments = "$($Results.Comments)`r`n" + "$($_.PSChildName) is missing the State property."
        }
        elseif ($reg.State -ne 146432) { #0x23C00
            $Found = $true
            $Results.Comments = "$($Results.Comments)`r`n" + "$($_.PSChildName) has the incorrect state value ($reg.state)"
        }
    }
    else {
        $Found = $true
        $Results.Comments = "$($Results.Comments)`r`n" + "$($_.PSChildName) is missing the Software Publishing Key"
    }

}

if (-not $Found) {
    $Results.Details = "All users have the correct setting set."
    $Results.Status = "NotAFinding"
}
else {
    $Results.Details = "Issues found. See comments for list."
    $Results.Status = "Open"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-7061 [$($Results.Status)]"

#Return results
return $Results