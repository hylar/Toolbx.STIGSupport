<#
.SYNOPSIS
    Pre Check for Windows_Server_2016_V1R9
#>

#Domain info
$domain=(gwmi Win32_NTDomain).DomainName | Select -First 1

if($domain){
    $HostType = $(
        $HT = (Get-WmiObject -Class Win32_OperatingSystem -Property ProductType).ProductType
        switch ($HT) {
            1 { "Workstation" }
            2 { "Domain Controller" }
            3 { "Member Server" }
        }
    )
}else{
    $HostType="Non-Domain"
}

# Pull secedit data to temp file
Write-Verbose "[$($MyInvocation.MyCommand)] Pulling secedit.exe data."
secedit.exe /export /areas SECURITYPOLICY /cfg c:\windows\temp\secEdit.txt
$secEdit=Get-Content "c:\windows\temp\secEdit.txt"

#Pull user rights
$userRights=Get-WmiObject -NameSpace Root\RSOP\Computer -Class RSOP_UserPrivilegeRight | Select userright, Accountlist

# Gather audit polices for use in vulnerability checks
Write-Verbose "[$($MyInvocation.MyCommand)] Pulling auditpol.exe data. "
$acctLogon=auditpol.exe /get /category:"Account Logon"
$acctMgmt=auditpol.exe /get /category:"Account Management"
$detTrack=auditpol.exe /get /category:"Detailed Tracking"
$dsAccess=auditpol.exe /get /category:"DS Access"
$logonOff=auditpol.exe /get /category:"Logon/Logoff"
$polChange=auditpol.exe /get /category:"Policy Change"
$privUse=auditpol.exe /get /category:"Privilege Use"
$system=auditpol.exe /get /category:"System"
$objAccess=auditpol.exe /get /category:"Object Access"

return @{
    domain      = $domain
    hostType    = $HostType
    secEdit     = $secEdit
    userRights  = $userRights
    acctLogon   = $acctLogon
    acctMgmt    = $acctMgmt
    detTrack    = $detTrack
    dsAccess    = $dsAccess
    logonOff    = $logonOff
    polChange   = $polChange
    privUse     = $privUse
    system      = $system
    objAccess   = $objAccess
    
}
