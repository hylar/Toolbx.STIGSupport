<#
.SYNOPSIS
    This checks for compliancy on V-8326.

    The directory server supporting (directly or indirectly) system access or resource authorization must run on a machine dedicated to that function.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-8326"

# Initial Variables
$Results = @{
    VulnID   = "V-8326"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
if ( $PreCheck.hostType -eq "Domain Controller") {
    #Check against default list of services that should be running. Any running service not on list will cause failure.
    [array]$defaultServices = "ACCMMBService","ACCMWatcherService","ActivID Shared Store Service","ADWS","Appinfo","BFE",
    "BITS","BrokerInfrastructure","CcmExec","CertPropSvc","CmRcService","COMSysApp","CryptSvc","DcomLaunch","Dfs","DFSR",
    "Dhcp","DiagTrack","DNS","Dnscache","DPS","DsmSvc","EFS","enterceptAgent","EventLog","EventSystem","FontCache","gpsvc",
    "HipMgmt","IKEEXT","InstallRoot","IsmServ","Kdc","KeyIso","LanmanServer","LanmanWorkstation","lmhosts","LSM",
    "macmnsvc","masvc","McAfeeAuditManager","McAfeeDLPAgentService","McAfeeFramework","McShield","McTaskManager","mfemms",
    "mfevtp","MpsSvc","MSDTC","NcbService","Netlogon","netprofm","NisSvc","NlaSvc","nsi","NTDS","PlugPlay","PolicyAgent",
    "Power","ProfSvc","RemoteRegistry","RpcEptMapper","RpcSs","SamSs","ScDeviceEnum","Schedule","SCPolicySvc","SENS",
    "SessionEnv","ShellHWDetection","SplunkForwarder","SystemEventsBroker","TermService","Themes","TimeBroker",
    "Tumbleweed Desktop Validator","UALSVC","UmRdpService","vds","VGAuthService","VMTools","W32Time","Wcmsvc","WerSvc",
    "WinHttpAutoProxySvc","Winmgmt","WinRM","wlidsvc","wuauserv","wudfsvc"
    [array]$running = (Get-Service | Where-Object Status -eq "Running")
    [int]$fail = 0
    foreach ($service in $running.Name) {
        if ($defaultServices -match "^$service$") {}
        else {
            [int]$fail = 1
        }
    }
    if ($fail -eq 0) {
        $Results.Status = "NotAFinding"
        $Results.Details = "All running services are as expected. See comments for details."
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Discovered unexpected running services; Please review! See comments for details."
    }
    $Results.Comments = $running | Select-Object DisplayName, Name, Status | Format-List | Out-String
    #Check against default list of features that should be installed. Any installed service not on list will cause failure.
    [array]$defaultFeatures = "AD-Domain-Services","DNS","FileAndStorage-Services","File-Services","FS-FileServer",
    "Storage-Services","NET-Framework-45-Features","NET-Framework-45-Core","NET-WCF-Services45",
    "NET-WCF-TCP-PortSharing45","GPMC","InkAndHandwritingServices","Server-Media-Foundation","RDC","RSAT",
    "RSAT-Role-Tools","RSAT-AD-Tools","RSAT-AD-PowerShell","RSAT-ADDS","RSAT-AD-AdminCenter","RSAT-ADDS-Tools",
    "RSAT-DNS-Server","User-Interfaces-Infra","Server-Gui-Mgmt-Infra","Desktop-Experience","Server-Gui-Shell",
    "PowerShellRoot","PowerShell","PowerShell-ISE","WoW64-Support"
    $installed = (Get-WindowsFeature | Where-Object Installed -eq $true)
    [int]$fail = 0
    foreach ($feature in $installed.Name) {
        if ($defaultFeatures -match "^$feature$") {}
        else {
            [int]$fail = 1
        }
    }
    if ($fail -eq 0) {
        $Results.Details = "All running services are as expected. See comments for details."
    }
    else {
        $Results.Status = "Open"
        $Results.Details = "Discovered unexpected running services; Please review! See comments for details."
    }
    $Results.Comments = ($Results.Comments + ($installed | Select-Object DisplayName, Name, Installed | Format-List | Out-String)
}
else {
    $Results.Status = "Not_Applicable"
    $Results.Details = "Check only applies to domain controllers."
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-8326 [$($Results.Status)]"

#Return results
return $Results
