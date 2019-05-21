<#
.SYNOPSIS
    This checks for compliancy on V-####

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "Checking - V-####"

# Initial Variables
$Results = @{
    VulnID   = "V-####"
    Details  = "$($PreCheck.EXEConfigs.Count)"
    Comments = ""
    Result   = ""
}

#Perform necessary check



#Return results
return $Results