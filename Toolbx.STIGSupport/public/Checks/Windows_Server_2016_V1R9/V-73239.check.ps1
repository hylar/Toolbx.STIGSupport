<#
.SYNOPSIS
    This checks for compliancy on V-73239.

    Systems must be maintained at a supported servicing level.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73239"

# Initial Variables
$Results = @{
    VulnID   = "V-73239"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$product=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name ProductName).ProductName
if($product -like "*Server 2016*"){
    $version=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name ReleaseID -ErrorAction Stop).ReleaseID
    $build=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name CurrentBuild).CurrentBuild
    if($version -eq 1607 -and $build -gt 14393){
        $Results.Details="Product: $product | Version: $version | Build: $build"
        $Results.Status="NotAFinding"
    }else{
        $Results.Details="Version or build is not correct. Product: $product | Version: $version | Build: $build"
        $Results.Status="Open"
    }
}else{
    $Results.Details="Unable to verify this is 2016, system product shows as: $product"
    $Results.Status="Open"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73239 [$($Results.Status)]"

#Return results
return $Results