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
        $2012R2MSCore,

        # Will Create Server 2012 R2 Domain Controller OS, .Net Framework 4, and IE11 Checklists.
        [Parameter()]
        [Switch]
        $2012R2DCCore,

        # Will Create Server 2016 OS, .Net Framework 4, and IE11 Checklists.
        [Parameter()]
        [Switch]
        $2016Core,

        # Will Create Windows 10 OS, .Net Framework 4, and IE11, Adobe Reader Continous, Chrome, Firefox, and Java Checklists
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

        $templates

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

        if ($Win10Core) {
            $core = @{
                "Win10" = $($templates | Where-Object { $_.Name -like "U_MS_Windows_10_STIG_*" }).fullname
                #TODO: There needs to be a better way to do this.
                "Win10Path" = "$Destination\$($HostName)_$($($($templates | Where-Object { $_.Name -like "U_MS_Windows_10_STIG_*" }).Name).Replace("_Manual-xccdf.xml",".xml"))"
                "IE11"    = $($templates | Where-Object { $_.Name -like "U_MS_IE11_STIG_*" }).fullname
                "IE11Path" = "$Destination\$($HostName)_$($($(split-path $core.IE11 -leaf)).Replace("_Manual-xccdf.xml",".xml"))"
            }

            #Write-Verbose "[$($MyInvocation.MyCommand)] Creating New Checklist from $(split-path $core.Win10 -leaf)"

            #$cklCreated += $core.Win10Path
            #ConvertTo-Checklist -XccdfPath $core.Win10 -Destination $core.Win10Path
            #Write-Verbose "[$($MyInvocation.MyCommand)] Created $($core.Win10Path)"

            $core
        }

        #$cklCreated
    }

}