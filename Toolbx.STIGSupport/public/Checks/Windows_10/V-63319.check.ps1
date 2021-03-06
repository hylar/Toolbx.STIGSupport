<#
.SYNOPSIS
    This checks for compliancy on V-63319.

    Domain-joined systems must use Windows 10 Enterprise Edition 64-bit version.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-63319"

# Initial Variables
$Results = @{
    VulnID   = "V-63319"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$partOfDomain = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
$operatingSystem = Get-WmiObject -Class Win32_OperatingSystem

if($partOfDomain){

    if($operatingSystem.OSArchitecture -ne "64-bit"){

        $Results.Details = "System type is not 64-bit."
        $Results.Status = "Open"

    }else{

        # Check OS Type
        if($operatingSystem.Caption -ne "Microsoft Windows 10 Enterprise"){

            $Results.Details = "System is Domain-joined and is not Windows 10 Enterprise."
            $Results.Status = "Open"

        }else{

            $Results.Details = "System is Domain-joined and is Windows 10 Enterprise."
            $Results.Status = "NotAFinding"

        }

    }

}else{

        $Results.Details = "System is standalone, this is NA"
        $Results.Status = "Not_Applicable"

}

#TODO: Populate the comments with the data
#Return results
return $Results
