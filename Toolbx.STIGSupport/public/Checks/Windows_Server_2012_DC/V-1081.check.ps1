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
$fail = 0
$failNames = @()
foreach ($item in $details) {
    #If any fixed drive is not NTFS, it is a finding
    if ($item.FileSystem -eq "NTFS" -or $item.FileSystem -eq "ReFS") {
        #Good
    }    else {
        $fail = 1
        $failNames += ("Drive letter '"+$item.DriveLetter+"' with name '"+$item.FileSystemLabel+"' is set to '"+$item.FileSystem+"'")
    }
}
if ($fail -eq 0) {
    $Results.Details = "All fixed drives found were formatted to NTFS or ReFS. See comments for details."
    $Results.Status = "NotAFinding"
    $Results.Comments = "-=Unexpected File Systems=-"
    $Results.Comments += $failNames | Format-List | Out-String
}
else {
    $Results.Status = "Open"
    $Results.Details = "Found fixed drives that were not formatted to NTFS or FS! See comments for details."
}
if($Results.Status -eq "NotAFinding"){$Results.Details = "All fixed drives are formatted as NTFS."}
$Results.Comments += "`r`n-=All Drives=-"
$Results.Comments += $details | Select-Object DriveLetter,FileSystemLabel,FileSystem,DriveType | Format-List | Out-String

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-1081 [$($Results.Status)]"

#Return results
return $Results
