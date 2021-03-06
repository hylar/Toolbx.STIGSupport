<#
.SYNOPSIS
    This checks for compliancy on V-3487.

    Necessary services must be documented to maintain a baseline to determine if additional, unnecessary services have been added to a system.

.PARAMETER PreCheck
    Input data as returned by the pre.check.ps1 script for this stig.
#>

[CmdletBinding()]
Param($PreCheck)

Write-Verbose "[$($MyInvocation.MyCommand)]Checking - V-3487"

# Initial Variables
$Results = @{
    VulnID   = "V-3487"
    RuleID   = ""
    Details  = ""
    Comments = ""
    Status   = "Not_Reviewed"
}

#Perform necessary check
( Get-Service | Select-Object DisplayName,StartType ) | Export-Csv c:\windows\temp\services.csv
$services = Import-Csv c:\windows\temp\services.csv

$baselineText = "Name,StartType`r`nApplication Experience,Manual`r`nApplication Identity,Manual`r`nApplication Information,Manual`r`nApplication Layer Gateway Service,Manual`r`nApplication Management,Manual`r`nBackground Intelligent Transfer Service,Automatic`r`nBackground Tasks Infrastructure Service,Automatic`r`nBase Filtering Engine,Automatic`r`nCertificate Propagation,Manual`r`nCNG Key Isolation,Manual`r`nCOM+ Event System,Automatic`r`nCOM+ System Application,Manual`r`nComputer Browser,Disabled`r`nCredential Manager,Manual`r`nCryptographic Services,Automatic`r`nDCOM Server Process Launcher,Automatic`r`nDevice Association Service,Manual`r`nDevice Install Service,Manual`r`nDevice Setup Manager,Manual`r`nDHCP Client,Automatic`r`nDiagnostic Policy Service,Automatic`r`nDiagnostic Service Host,Manual`r`nDiagnostic System Host,Manual`r`nDistributed Link Tracking Client,Automatic`r`nDistributed Transaction Coordinator,Automatic`r`nDNS Client,Automatic`r`nEncrypting File System (EFS),Manual`r`nExtensible Authentication Protocol,Manual`r`nFunction Discovery Provider Host,Manual`r`nFunction Discovery Resource Publication,Manual`r`nGroup Policy Client,Automatic`r`nHealth Key and Certificate Management,Manual`r`nHuman Interface Device Access,Manual`r`nHyper-V Data Exchange Service,Manual`r`nHyper-V Guest Shutdown Service,Manual`r`nHyper-V Heartbeat Service,Manual`r`nHyper-V Remote Desktop Virtualization Service,Manual`r`nHyper-V Time Synchronization Service,Manual`r`nHyper-V Volume Shadow Copy Requestor,Manual`r`nIKE and AuthIP IPsec Keying Modules,Manual`r`nInteractive Services Detection,Manual`r`nInternet Connection Sharing (ICS),Disabled`r`nIP Helper,Automatic`r`nIPsec Policy Agent,Manual`r`nKDC Proxy Server service (KPS),Manual`r`nKtmRm for Distributed Transaction Coordinator,Manual`r`nLink-Layer Topology Discovery Mapper,Manual`r`nLocal Session Manager,Automatic`r`nMicrosoft iSCSI Initiator Service,Manual`r`nMicrosoft Software Shadow Copy Provider,Manual`r`nMultimedia Class Scheduler,Manual`r`nNet.Tcp Port Sharing Service,Disabled`r`nNetlogon,Manual`r`nNetwork Access Protection Agent,Manual`r`nNetwork Connections,Manual`r`nNetwork Connectivity Assistant,Manual`r`nNetwork List Service,Manual`r`nNetwork Location Awareness,Automatic`r`nNetwork Store Interface Service,Automatic`r`nOptimize drives,Manual`r`nPerformance Counter DLL Host,Manual`r`nPerformance Logs & Alerts,Manual`r`nPlug and Play,Manual`r`nPortable Device Enumerator Service,Manual`r`nPower,Automatic`r`nPrint Spooler,Automatic`r`nPrinter Extensions and Notifications,Manual`r`nProblem Reports and Solutions Control Panel Support,Manual`r`nRemote Access Auto Connection Manager,Manual`r`nRemote Access Connection Manager,Manual`r`nRemote Desktop Configuration,Manual`r`nRemote Desktop Services,Manual`r`nRemote Desktop Services UserMode Port Redirector,Manual`r`nRemote Procedure Call (RPC),Automatic`r`nRemote Procedure Call (RPC) Locator,Manual`r`nRemote Registry,Automatic`r`nResultant Set of Policy Provider,Manual`r`nRouting and Remote Access,Disabled`r`nRPC Endpoint Mapper,Automatic`r`nSecondary Logon,Manual`r`nSecure Socket Tunneling Protocol Service,Manual`r`nSecurity Accounts Manager,Automatic`r`nServer,Automatic`r`nShell Hardware Detection,Automatic`r`nSmart Card,Disabled`r`nSmart Card Removal Policy,Manual`r`nSNMP Trap,Manual`r`nSoftware Protection,Automatic`r`nSpecial Administration Console Helper,Manual`r`nSpot Verifier,Manual`r`nSSDP Discovery,Disabled`r`nSuperfetch,Manual`r`nSystem Event Notification Service,Automatic`r`nTask Scheduler,Automatic`r`nTCP/IP NetBIOS Helper,Automatic`r`nTelephony,Manual`r`nThemes,Automatic`r`nThread Ordering Server,Manual`r`nUPnP Device Host,Disabled`r`nUser Access Logging Service,Automatic`r`nUser Profile Service,Automatic`r`nVirtual Disk,Manual`r`nVolume Shadow Copy,Manual`r`nWindows All-User Install Agent,Manual`r`nWindows Audio,Manual`r`nWindows Audio Endpoint Builder,Manual`r`nWindows Color System,Manual`r`nWindows Driver Foundation - User-mode Driver Framework,Manual`r`nWindows Error Reporting Service,Manual`r`nWindows Event Collector,Manual`r`nWindows Event Log,Automatic`r`nWindows Firewall,Automatic`r`nWindows Font Cache Service,Automatic`r`nWindows Installer,Manual`r`nWindows Licensing Monitoring Service,Automatic`r`nWindows Management Instrumentation,Automatic`r`nWindows Modules Installer,Manual`r`nWindows Remote Management (WS-Management),Automatic`r`nWindows Store Service (WSService),Manual`r`nWindows Time,Manual`r`nWindows Update,Manual`r`nWinHTTP Web Proxy Auto-Discovery Service,Manual`r`nWired AutoConfig,Manual`r`nWMI Performance Adapter,Manual`r`nWorkstation,Automatic"
$baselineText | Out-File c:\windows\temp\baseline.csv
$baseline = Import-Csv c:\windows\temp\baseline.csv
$fail = 0
$failNames = @()

foreach ($service in $services) {
    if (($baseline -match $service.DisplayName) -match $service.StartType) {
        #Good
    }    else {
        $fail = 1
        if ($baseline -match $service.DisplayName) {
            $failNames += ("'"+$service.DisplayName+"' is set to '"+$service.StartType+"' when it should be: "+($baseline -match $service.DisplayName).StartType)
        }        else {
            $failNames += ("'"+$service.DisplayName+"' is not on baseline!")
        }
    }
}
if ($fail -eq 0) {
    $Results.Status = "NotAFinding"
    $Results.Details = "No difference with baseline was found with system services. See comments for list of all services and startup type."
    $Results.Comments = $services | Format-List | Out-String
}
else {
    $Results.Status = "Open"
    $Results.Details = "Services were found that differ from expected baseline, please review! See comments for services that do not match baseline."
    $Results.Comments = $failNames
}

Write-Verbose "[$($MyInvocation.MyCommand)] Completed Checking - V-3487 [$($Results.Status)]"

#Return results
return $Results
