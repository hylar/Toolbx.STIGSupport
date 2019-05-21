function Set-ChecklistHostData {

    [CmdletBinding()]
    Param(

        # Specify the Checklist to update.
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [XML]
        $Checklist
    )

    $FQDN = (Get-WmiObject win32_computersystem).DNSHostName + "." + (Get-WmiObject win32_computersystem).Domain
    $IP = [System.Net.Dns]::GetHostByName($env:computerName).Addresslist.IPAddressToString
    $MAC = (Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.IpAddress -eq $IP }).MACAddress
    $HostType = $(
        $HT = (Get-WmiObject -Class Win32_OperatingSystem -Property ProductType).ProductType

        switch ($HT) {
            1 { "Workstation" }
            2 { "Domain Controller" }
            3 { "Member Server" }
        }
    )

    $Checklist.CHECKLIST.ASSET.HOST_NAME = $env:computerName
    $Checklist.CHECKLIST.ASSET.HOST_FQDN = $FQDN
    $Checklist.CHECKLIST.ASSET.HOST_IP = $IP
    $Checklist.CHECKLIST.ASSET.HOST_MAC = $Mac
    $Checklist.CHECKLIST.ASSET.ROLE = $HostType

}