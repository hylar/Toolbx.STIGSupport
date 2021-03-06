<#
.SYNOPSIS
    This checks for compliancy on V-39325.

    Active Directory Group Policy objects must be configured with proper audit settings.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-39325"

# Initial Variables
$Results = @{
    VulnID   = "V-39325"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
if ($PreCheck.hostType -eq "Domain Controller") {
    Import-Module ActiveDirectory
    $gpos = (Get-Gpo -All)
    foreach ($gpo in $gpos) {
        $audit = (Get-Acl -Audit -Path ('AD:'+$gpo.Path)).Audit
        $fail = 0
        if ($audit.Count -eq 4) {
            foreach ($item in $audit) {
                if (
                    $item.ActiveDirectoryRights -match "GenericAll" -and
                    $item.AuditFlags -match "Failure" -and
                    $item.IdentityReference -match "Everyone" -and
                    $item.IsInherited -match "True" -and
                    $item.InheritanceType -match "All"
                ) {
                    #Match default/expected entry
                }
                elseif (
                    $item.ActiveDirectoryRights -match "WriteProperty, WriteDacl" -and
                    $item.AuditFlags -match "Success" -and
                    $item.IdentityReference -match "Everyone" -and
                    $item.IsInherited -match "True" -and
                    $item.InheritanceType -match "All"
                ) {
                    #Match default/expected entry
                }
                elseif (
                    $item.ActiveDirectoryRights -match "WriteProperty" -and
                    $item.AuditFlags -match "Success" -and
                    $item.IdentityReference -match "Everyone" -and
                    $item.IsInherited -match "True" -and
                    $item.InheritanceType -match "Descendents"
                ) {
                    #Match default/expected entry (two of these ones)
                }
                else{
                    $fail = 1
                }
            }
        }
        else {
            $fail = 1
        }
        if ($fail -eq 1) {
            $Results.Comments += ("`r`n-------------------------------")
            $Results.Comments += ("`r`nGPO '"+$gpo.DisplayName+"' has unexpected rights!")
            $Results.Comments += $audit | Select-Object AuditFlags,IdentityReference,ActiveDirectoryRights,InheritanceType | Format-List | Out-String
        }
    }
    if ($Results.Comments.Length -gt 0) {
        $Results.Status = "Open"
        $Results.Details = "Found GPOs with unexpected audit rights; Please review! See comments for details."
    }
    else {
        $Results.Status = "NotAFinding"
        $Results.Details = "Found no GPOs with audit rights beyond expected values."
    }
}
else {
    $Results.Status = "Not_Applicable"
    $Results.Details = "Check only applies to Domain Controllers."
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-39325 [$($Results.Status)]"

#Return results
return $Results
