function New-Checklist {

    [CmdletBinding()]
    param (

        # Specify the path to save the new checklist(s) to.
        [Parameter(Mandatory = $true)]
        [string]
        $Destination,

        # Specify the HostName for the new checklist(s). If no name is provided, the local computername will be used.
        [Parameter()]
        [string]
        $HostName = $ENV:COMPUTERNAME,

        # Will Create Server 2012 R2 Member OS, .Net Framework 4, and IE11 Checklists.
        [Parameter()]
        [Switch]
        $Win2012R2MSCore,

        # Will Create Server 2012 R2 Domain Controller OS, .Net Framework 4, and IE11 Checklists.
        [Parameter()]
        [Switch]
        $Win2012R2DCCore,

        # Will Create Server 2016 OS, .Net Framework 4, and IE11 Checklists.
        [Parameter()]
        [Switch]
        $Win2016Core,

        # Will Create Windows 10 OS, .Net Framework 4, and IE11, Adobe Reader Continous, Chrome, Firefox, and Java 8 Checklists
        [Parameter()]
        [Switch]
        $Win10Core
    )

    DynamicParam {
        $RuntimeParamDic = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
        $AttribColl = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
        $ParamAttrib = New-Object System.Management.Automation.ParameterAttribute
        $ParamAttrib.Mandatory = $Mandatory.IsPresent
        $ParamAttrib.ParameterSetName = '__AllParameterSets'
        $ParamAttrib.ValueFromPipeline = $ValueFromPipeline.IsPresent
        $ParamAttrib.ValueFromPipelineByPropertyName = $ValueFromPipelineByPropertyName.IsPresent
        $AttribColl.Add($ParamAttrib)
        $AttribColl.Add((New-Object System.Management.Automation.ValidateSetAttribute((Get-ChildItem $("$PSScriptRoot\..\..\tools\STIG Data\Current") -File | Select-Object -ExpandProperty Name))))
        $RuntimeParam = New-Object System.Management.Automation.RuntimeDefinedParameter('XCCDFTemplates', [string], $AttribColl)
        $RuntimeParamDic.Add('XCCDFTemplates', $RuntimeParam)
        return $RuntimeParamDic
    }

    process {

        [array]$cklCreated = @()

        $templates = Get-ChildItem $("$PSScriptRoot\..\..\tools\STIG Data\Current")

        If ($(Test-Path -Path $Destination) -eq $false) {
            New-Item -Path $Destination -ItemType Directory -Force | out-null
        }

        # Check is a specific checklist was selected. If so Create that checklist.
        if ($PSBoundParameters.XCCDFTemplates) {

            Write-Verbose "[$($MyInvocation.MyCommand)] Creating New Checklist from $($PSBoundParameters.XCCDFTemplates)"

            $xccdfTempPath = "$PSScriptRoot\..\..\tools\STIG Data\Current\" + $PSBoundParameters.XCCDFTemplates


            $xccdfNewPath = "$Destination\$($HostName)_$($($PSBoundParameters.XCCDFTemplates).Replace("_Manual-xccdf.xml",".xml"))"
            Write-Verbose "[$($MyInvocation.MyCommand)] Saving to $xccdfNewPath"

            $cklCreated += $xccdfNewPath

            ConvertTo-Checklist -XccdfPath $xccdfTempPath -Destination $xccdfNewPath
            Write-Verbose "[$($MyInvocation.MyCommand)] Created $xccdfNewPath"
        }

        [Hashtable]$core = @{ }

        If ($Win10Core) { $core.Add("WIN10", $($templates | Where-Object { $_.Name -like "U_MS_Windows_10_STIG_*" }).fullname) }

        If ($Win10Core -or $Win2012R2MSCore -or $Win2012R2DCCore -or $Win2016Core) {
            $core.Add("IE11", $($templates | Where-Object { $_.Name -like "U_MS_IE11_STIG_*" }).fullname)
        }

        If ($Win10Core) { $core.Add("Chrome", $($templates | Where-Object { $_.Name -like "U_Google_Chrome_STIG_*" }).fullname) }

        If ($Win10Core) { $core.Add("ARC", $($templates | Where-Object { $_.Name -like "U_Adobe_Acrobat_Reader_DC_Continuous_*" }).fullname) }

        If ($Win10Core -or $Win2012R2MSCore -or $Win2012R2DCCore -or $Win2016Core) {
            $core.Add("DNF", $($templates | Where-Object { $_.Name -like "U_MS_DotNet_Framework_4-0_STIG_*" }).fullname)
        }

        If ($Win10Core) { $core.Add("FF", $($templates | Where-Object { $_.Name -like "U_Mozilla_FireFox_STIG_*" }).fullname) }

        If ($Win10Core) { $core.Add("JRE8", $($templates | Where-Object { $_.Name -like "U_Oracle_JRE_8_Windows_STIG_*" }).fullname) }

        If ($Win2012R2MSCore) { $core.Add("2k12MS", $($templates | Where-Object { $_.Name -like "U_MS_Windows_2012_and_2012_R2_MS_STIG_*" }).fullname) }

        If ($Win2012R2DCCore) { $core.Add("2k12DC", $($templates | Where-Object { $_.Name -like "U_MS_Windows_2012_and_2012_R2_DC_STIG_*" }).fullname) }

        If ($Win2016Core) { $core.Add("2k16", $($templates | Where-Object { $_.Name -like "U_MS_Windows_Server_2016_STIG_*" }).fullname) }

        # Create Checklists
        foreach ($key in $core.keys) {

            Write-Verbose "[$($MyInvocation.MyCommand)] Creating New Checklist from $(split-path $core[$key] -leaf)"

            $saveTo = "$Destination\$($HostName)_$($($(split-path $core[$key] -leaf)).Replace("_Manual-xccdf.xml",".xml"))"

            ConvertTo-Checklist -XccdfPath $core[$key] -Destination $saveTo -HostName $HostName

            $cklCreated += $saveTo

            Write-Verbose "[$($MyInvocation.MyCommand)] Created $saveTo"
        }

        $cklCreated
    }

}