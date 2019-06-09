
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
        $HostName = $ENV:COMPUTERNAME

    )

    DynamicParam {

        #Create Parameter Dictionary
        $RuntimeParamDic = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary

        $AttribColl = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
        $ParamAttrib = New-Object System.Management.Automation.ParameterAttribute
        $ParamAttrib.Mandatory = $Mandatory.IsPresent
        $ParamAttrib.ParameterSetName = '__AllParameterSets'
        $ParamAttrib.ValueFromPipeline = $ValueFromPipeline.IsPresent
        $ParamAttrib.ValueFromPipelineByPropertyName = $ValueFromPipelineByPropertyName.IsPresent
        $AttribColl.Add($ParamAttrib)
        $AttribColl.Add( ( New-Object System.Management.Automation.ValidateSetAttribute($($($(Get-Content -Raw -Path "$PSScriptRoot\..\..\Toolbx.STIGSupport.config" | ConvertFrom-Json).NewCheckListOptions.Name) + $(if($(Test-Path "$env:USERPROFILE\Documents\WindowsPowerShell\Toolbx.STIGSupport.config") -eq $true){ $(Get-Content -Raw -Path "$env:USERPROFILE\Documents\WindowsPowerShell\Toolbx.STIGSupport.config" | ConvertFrom-Json).NewCheckListOptions.Name})))))
        $RuntimeParam = New-Object System.Management.Automation.RuntimeDefinedParameter('ChecklistSet', [string], $AttribColl)
        $RuntimeParamDic.Add('ChecklistSet', $RuntimeParam)

        $AttribColl1 = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
        $ParamAttrib1 = New-Object System.Management.Automation.ParameterAttribute
        $ParamAttrib1.Mandatory = $Mandatory.IsPresent
        $ParamAttrib1.ParameterSetName = '__AllParameterSets'
        $ParamAttrib1.ValueFromPipeline = $ValueFromPipeline.IsPresent
        $ParamAttrib1.ValueFromPipelineByPropertyName = $ValueFromPipelineByPropertyName.IsPresent
        $AttribColl1.Add($ParamAttrib1)
        $AttribColl1.Add((New-Object System.Management.Automation.ValidateSetAttribute((Get-ChildItem $("$PSScriptRoot\..\..\tools\STIG Data\Current") -File | Select-Object -ExpandProperty Name))))
        $RuntimeParam1 = New-Object System.Management.Automation.RuntimeDefinedParameter('XCCDFTemplates', [string], $AttribColl1)
        $RuntimeParamDic.Add('XCCDFTemplates', $RuntimeParam1)

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

        # Retrieve Custom Set if provided and create checklists.
        if ($PSBoundParameters.ChecklistSet) {

            Write-Verbose "[$($MyInvocation.MyCommand)] Creating New Checklist from $($PSBoundParameters.ChecklistSet) Set"

            $PSBoundParameters.ChecklistSet | ForEach-Object {

                $create = $_
                $ckl = $($templates | Where-Object { $_.Name -like "$create*" }).fullname
                $xccdfNewPath = "$Destination\$($HostName)_$($($ckl).Replace("_Manual-xccdf.xml",".xml"))"

                ConvertTo-Checklist -XccdfPath $ckl -Destination $xccdfNewPath

                Write-Verbose "[$($MyInvocation.MyCommand)] Created $xccdfNewPath"

                $cklCreated += $xccdfNewPath
            }

        }

    }

}