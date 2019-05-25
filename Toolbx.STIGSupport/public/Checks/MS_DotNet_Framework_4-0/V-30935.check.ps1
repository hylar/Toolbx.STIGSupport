<#
.SYNOPSIS
    This checks for compliancy on V-30935.

    .NET must be configured to validate strong names on full-trust assemblies.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-30935"

# Initial Variables
$Results = @{
    VulnID   = "V-30935"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

$Found = $false;

#Perform necessary check
@("HKLM:\SOFTWARE\Microsoft\.NETFramework\", "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\") | ForEach-Object {

    if ($(Test-Path $_) -eq $true) {

        $property = (Get-ItemProperty -Path $_ -ErrorAction SilentlyContinue).AllowStrongNameBypass

        if ($property -eq $null) {
            $Results.Comments = "$($Results.Comments)`r`n" + "$_ - AllowStrongNameBypass does not exist"
            $found = $true
        }
        elseif ($property -eq 1) {
            $Results.Comments = "$($Results.Comments)`r`n" + "$_ - AllowStrongNameBypass is set to '1'"
            $found = $true
        }
        else {
            $Results.Comments = "$($Results.Comments)`r`n" + "$_ - AllowStrongNameBypass is set to $($property.ToString())"
        }

    }
    else {

        $Results.Comments = "$($Results.Comments)`r`n" + "$_ - does not exist"
        $found = $true

    }

}

if (-not $Found) {
    $Results.Details = "No keys were found with an AllowStringNameBypass value missing or set to '1'."
    $Results.Status = "NotAFinding"
}
else {
    $Results.Details = "There are keys found with an AllowStringNameBypass value missing or set to '1'. See comments for a list."
    $Results.Status = "Open"
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-30935 [$($Results.Status)]"

#Return results
return $Results