<#
.SYNOPSIS
    Pre Check for IE11_STIG_V1R17
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


return @{
    domain     = $domain
    hostType   = $hostType
}
