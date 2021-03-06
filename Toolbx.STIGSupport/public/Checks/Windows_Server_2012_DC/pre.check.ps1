<#
.SYNOPSIS
    Pre Check for Windows_Server_2012_V2R15 (DC) v2r16

Checks differing from MS check:
V-1127
V-1155
V-2376
V-2377
V-2378
V-2379
V-2380
V-3338
V-4407
V-4408
V-8316
V-8317
V-8322
V-8324
V-8326
V-8327
V-14783
V-14797
V-14798
V-14820
V-14831
V-15488
V-26470
V-26473
V-26483
V-26484
V-26485
V-26486
V-26487
V-26531
V-26683
V-30016
V-33663
V-33664
V-33665
V-33666
V-33673
V-39325
V-39326
V-39327
V-39328
V-39329
V-39330
V-39331
V-39332
V-39333
V-39334
V-91777
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
