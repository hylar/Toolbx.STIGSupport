<#
.SYNOPSIS
    Pre Check for MS_DotNet_Framework_4-0
#>

# Gather all .exe.config files for processing in script
Write-Verbose "Caching *.exe.config files. This will take time."

$EXEConfigFiles += Get-PSDrive -PSProvider FileSystem | Select-Object Root | foreach-object {
    Get-ChildItem $_.Root -Filter "*.exe.config" -ErrorAction ignore -Recurse
}


# Gather all machine.config files for processing in script
Write-Verbose "Caching machine.config files. "

$MachineConfigFiles = @()
$MachineConfigFiles += Get-ChildItem "C:\Windows\Microsoft.NET\Framework\v4.0.30319" -Filter "machine.config" -ErrorAction ignore -Recurse
$MachineConfigFiles += Get-ChildItem "C:\Windows\Microsoft.NET\Framework64\v4.0.30319" -Filter "machine.config" -ErrorAction ignore -Recurse

return @{
    EXEConfigs     = $EXEConfigFiles.FullName
    MachineConfigs = $MachineConfigFiles.FullName
}

