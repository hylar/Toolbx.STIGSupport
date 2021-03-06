<#
.SYNOPSIS
    Pre Check for Windows_Server_2012_V2R15
#>

#Domain info
$domain = (Get-WmiObject Win32_NTDomain).DomainName | Select-Object -First 1

if ($domain) {
    $hostType = $(
        $ht = (Get-WmiObject -Class Win32_OperatingSystem -Property ProductType).ProductType
        switch ($ht) {
            1 { "Workstation" }
            2 { "Domain Controller" }
            3 { "Member Server" }
        }
    )
}
else {
    $hostType = "Non-Domain"
}

# Pull secedit data to temp file
Write-Verbose "[$($MyInvocation.MyCommand)] Pulling secedit.exe data."
secedit.exe /export /areas SECURITYPOLICY GROUP_MGMT USER_RIGHTS REGKEYS FILESTORE SERVICES /cfg c:\windows\temp\secEdit.txt
$secEdit = Get-Content "c:\windows\temp\secEdit.txt"
#$secEdit=Get-WmiObject -NameSpace Root\RSOP\Computer -Class RSOP_SecuritySettingBoolean | Select-Object KeyName,status

#Pull user rights
$userRights = Get-WmiObject -NameSpace Root\RSOP\Computer -Class RSOP_UserPrivilegeRight | Select-Object userright, Accountlist

# Gather audit polices for use in vulnerability checks
Write-Verbose "[$($MyInvocation.MyCommand)] Pulling auditpol.exe data. "
$acctLogon = auditpol.exe /get /category:"Account Logon"
$acctMgmt = auditpol.exe /get /category:"Account Management"
$detTrack = auditpol.exe /get /category:"Detailed Tracking"
$dsAccess = auditpol.exe /get /category:"DS Access"
$logonOff = auditpol.exe /get /category:"Logon/Logoff"
$polChange = auditpol.exe /get /category:"Policy Change"
$privUse = auditpol.exe /get /category:"Privilege Use"
$system = auditpol.exe /get /category:"System"
$objAccess = auditpol.exe /get /category:"Object Access"

return @{
    domain     = $domain
    hostType   = $hostType
    secEdit    = $secEdit
    userRights = $userRights
    acctLogon  = $acctLogon
    acctMgmt   = $acctMgmt
    detTrack   = $detTrack
    dsAccess   = $dsAccess
    logonOff   = $logonOff
    polChange  = $polChange
    privUse    = $privUse
    system     = $system
    objAccess  = $objAccess

}
