<#
.SYNOPSIS
    This checks for compliancy on V-7055.

    Digital signatures assigned to strongly named assemblies must be verified.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-7055"

# Initial Variables
$Results = @{
    VulnID   = "V-7055"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$keys = @()
$keys += Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\StrongName\Verification\" -ErrorAction SilentlyContinue
$keys += Get-ChildItem -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\StrongName\Verification\" -ErrorAction SilentlyContinue

if ($keys.Length -eq 0) {
    $Results.Details = "No keys found under HKLM:\SOFTWARE\Microsoft\StrongName\Verification\ or HKLM:\SOFTWARE\Wow6432Node\Microsoft\StrongName\Verification\"
    $Results.Status = "NotAFinding"
}
else {

    $Results.Comments = "Keys Found`r`n"
    $keys | ForEach-Object {
        $Results.Comments = "$($Results.Comments)`r`n" + $_.Name
    }

    $Results.Details = "There were keys found under HKLM:\SOFTWARE\Microsoft\StrongName\Verification\ or HKLM:\SOFTWARE\Wow6432Node\Microsoft\StrongName\Verification\. See comments for a list."
    $Results.Status = "Open"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-7055 [$($Results.Status)]"

#Return results
return $Results