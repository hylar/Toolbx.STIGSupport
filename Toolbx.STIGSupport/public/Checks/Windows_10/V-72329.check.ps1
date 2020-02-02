<#
.SYNOPSIS
    This checks for compliancy on V-72329.

    Run as different user must be removed from context menus.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-72329"

# Initial Variables
[string]$keyPath1 = "HKLM:\SOFTWARE\Classes\batfile\shell\runasuser\"
[string]$keyPath2 = "HKLM:\SOFTWARE\Classes\cmdfile\shell\runasuser\"
[string]$keyPath3 = "HKLM:\SOFTWARE\Classes\exefile\shell\runasuser\"
[string]$keyPath4 = "HKLM:\SOFTWARE\Classes\mscfile\shell\runasuser\"
[string]$valueName = "SuppressionPolicy"
[int]$pass = 4096
[string]$vulnID = "V-72329"
$Results = @{
    VulnID   = $vulnID
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
foreach ($keyPath in $keyPath1 $keyPath2 $keyPath3 $keyPath4) {
	$NewResults = Compare-RegistryDWord -KeyPath $keyPath -ValueName $valueName -Expected $pass -ErrorAction SilentlyContinue;
	if ($NewResults.Status -eq "Open" -or $Results.Status -eq "Open"){
		$Results.Status = "Open"
	}
	$Results.Details += "; " + $NewResults.Details;
	$Results.Comments += "; " + $NewResults.Comments;
}
$Results.Details.TrimStart("; ");
$Results.Comments.TrimStart("; ");
Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-72329 [$($Results.Status)]"

#Return results
return $Results
