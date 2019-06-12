<#
.SYNOPSIS
    This checks for compliancy on V-1081.

    Local volumes must use a format that supports NTFS attributes.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-1081"

# Initial Variables
$Results = @{
    VulnID   = "V-1081"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
$details = (Get-Volume | ? {$_.DriveType -eq 'Fixed'})
foreach ($item in $details) {
    #If any fixed drive is not NTFS, it is a finding
    if (($item.FileSystemType -eq "NTFS" -or $item.FileSystemType -eq "ReFS") -and $Results.Status -ne "Open") {
        $Results.Details = "All fixed drives found were formatted to NTFS or ReFS. See comments."
        $Results.Status = "NotAFinding"
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Found fixed drives that were not formatted to NTFS or FS! See comments."
    }
}
if($Results.Status -eq "NotAFinding"){$Results.Details = "All fixed drives are formatted as NTFS."}
$Results.Comments = $details | Out-String

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-1081 [$($Results.Status)]"

#Return results
return $Results
