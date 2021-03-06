<#
.SYNOPSIS
    This checks for compliancy on V-1073.

    Systems must be maintained at a supported service pack level.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-1073"

# Initial Variables
$Results = @{
    VulnID   = "V-1073"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$product = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name ProductName).ProductName
if ($product -like "Windows Server 2012*") {
    [decimal]$version = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name CurrentVersion -ErrorAction Stop).CurrentVersion
    [int]$build = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name CurrentBuild).CurrentBuild
    if ($version -ge 6.2 -and $build -ge 9200) {
        $Results.Details = "Verified correct version of Server 2012. See comments for details."
        $Results.Comments = "Product: $product | Version: $version | Build: $build"
        $Results.Status = "NotAFinding"
    }
    else {
        $Results.Details = "Version or build is not correct! See comments for details."
        $Results.Comments = "Product: $product | Version: $version | Build: $build"
        $Results.Status = "Open"
    }
}
else {
    $Results.Details = "Unable to verify this is Server 2016! See comments for details."
    $Results.Comments = "Product: $product | Version: $version | Build: $build"
    $Results.Status = "Open"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-1073 [$($Results.Status)]"

#Return results
return $Results
