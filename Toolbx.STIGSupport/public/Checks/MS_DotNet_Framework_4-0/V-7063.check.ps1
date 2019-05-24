<#
.SYNOPSIS
    This checks for compliancy on V-7063.

    The Trust Providers Software Publishing State must be set to 0x23C00.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)] Checking - V-7063"

# Initial Variables
$Results = @{
    VulnID   = "V-7063"
    RuleID   = ""
    Details  = "Manual check required. See Comments and update check."
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
#Need further research on check from DISA to see if we can automate.

$Data = &("C:\Windows\Microsoft.NET\Framework64\v4.0.30319\caspol.exe") -m -lg

$Results.Comments = $Data | Out-String

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-7063 [$($Results.Status)]"

#Return results
return $Results