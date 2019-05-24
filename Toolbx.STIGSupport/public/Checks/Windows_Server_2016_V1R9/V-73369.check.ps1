<#
.SYNOPSIS
    This checks for compliancy on V-73369.

    Permissions on the Active Directory data files must only allow System and Administrators access.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-73369"

# Initial Variables
$Results = @{
    VulnID   = "V-73369"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$keyPath="SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
$valueName="Database log files path"
$key=(Get-ItemProperty HKLM:\$keyPath -Name $valueName)
if(!$key){
    $Results.Details="Registry value at $keyPath with name $valueName was not found!"
    $Results.Status="Open"
}else{
    [string]$value=$key.$valueName
    if($value -eq "C:\Windows\NTDS"){
        $Results.Details="$key"
        $Results.Status="NotAFinding"
    }else{
        Set-Location $value
        $icacls=icacls *.*
        $Results.Details="Database log files path is non-standard, please review rights:`r`n$icacls"
        $Results.Status="Open"
    }
}
$keyPath2="SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
$valueName2="DSA Database file"
$key=(Get-ItemProperty HKLM:\$keyPath2 -Name $valueName2)
if(!$key){
    $Results.Details+="Registry value at $keyPath2 with name $valueName2 was not found!"
    $Results.Status="Open"
}else{
    [string]$value=$key.$valueName2
    if($value -eq "C:\Windows\NTDS\ntds.dit" -and $Results.Status -eq "NotAFinding"){
        $Results.Details+="`r`n$key"
        $Results.Status="NotAFinding"
    }else{
        $path=($value -split [regex]::escape("\"))
        $path=$path | Select -First ($path.Count-1)
        $path=[string]::Join("\",$path)
        Set-Location $path
        $icacls=icacls *.*
        $Results.Details+="`r`nDatabase file path is non-standard, please review rights:`r`n$icacls"
        $Results.Status="Open"
    }
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-73369 [$($Results.Status)]"

#Return results
return $Results
