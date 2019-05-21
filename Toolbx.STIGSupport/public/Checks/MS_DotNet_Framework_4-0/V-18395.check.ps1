<#
.SYNOPSIS
    This checks for compliancy on V-####

.PARAMETER BeginData
    Input data as returned by the begin.ps1 script for this stig. Maybe null if one is not provided.
#>

[CmdletBinding()]
Param($PreCheckData)

Write-Verbose "Checking - V-####"

# Initial Variables
$Results = @{
    VulnID   = "V-####"
    Details  = ""
    Comments = ""
    Result   = ""
}

#Perform necessary check



#Return results
return $Results