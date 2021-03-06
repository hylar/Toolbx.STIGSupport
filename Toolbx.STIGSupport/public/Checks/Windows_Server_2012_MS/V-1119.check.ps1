<#
.SYNOPSIS
    This checks for compliancy on V-1119.

    The system must not boot into multiple operating systems (dual-boot).

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-1119"

# Initial Variables
$Results = @{
    VulnID   = "V-1119"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$bootInfo = BCDEDIT
if (($bootInfo -match "identifier").Count -eq 2 -and ($bootInfo -match "Windows Server 2012").Count -eq 1){
    $Results.Status = "NotAFinding"
    $Results.Details = "Only one boot entry exists and it is for Windows Server 2012. See comments for details."
}
else {
    $Results.Status = "Open"
    $Results.Details = "Multiple boot entries exist or the existing entry is NOT for Windows Server 2012, please review! See comments for details."
}
$Results.Comments = $bootInfo | Out-String

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-1119 [$($Results.Status)]"

#Return results
return $Results
