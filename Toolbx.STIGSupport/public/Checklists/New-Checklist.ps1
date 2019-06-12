
function New-Checklist {

    <#
        .SYNOPSIS
            Creates new STIG Checklists.

        .DESCRIPTION
            Creates new STIG Checklist from a predefined set within the module. This function also allows users to create STIG Sets so mutltiple STIG Checklists can be created at the same time. If you need to create a STIG Checklist from a template that is not in this module, use the ConvertTo-Checklist function.

        .PARAMETER ChecklistSet
            Specify a checklist set that will be used to create STIG Checklists for the given host.

        .PARAMETER XCCDFTemplates
            Specify a XCCDF Template to be used to create a new STIG Checklist. The list of templates are maintained within the module and get updated when new STIG checklists are releasesed.

        .EXAMPLE
            PS C:\> New-Checklist -Destination C:\Temp\Checklists -ChecklistSet 'Windows 10 - Core'

            This examples shows the function being called to create a set of checklists that are apart of 'Windows 10 - Core'.

        .OUTPUTS
            fullpaths to checklists that where created. [String[]]

        .NOTES
            None
    #>

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
        $AttribColl.Add( ( New-Object System.Management.Automation.ValidateSetAttribute($($($(Get-Content -Raw -Path "$PSScriptRoot\..\..\Toolbx.STIGSupport.config" | ConvertFrom-Json).NewCheckListOptions.Name) + $(if ($(Test-Path "$env:USERPROFILE\Documents\WindowsPowerShell\Toolbx.STIGSupport.config") -eq $true) { $(Get-Content -Raw -Path "$env:USERPROFILE\Documents\WindowsPowerShell\Toolbx.STIGSupport.config" | ConvertFrom-Json).NewCheckListOptions.Name })))))
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

            try {
                Write-Verbose "[$($MyInvocation.MyCommand)] Creating New Checklist from $($PSBoundParameters.XCCDFTemplates)"

                $xccdfTempPath = "$PSScriptRoot\..\..\tools\STIG Data\Current\" + $PSBoundParameters.XCCDFTemplates


                $xccdfNewPath = "$Destination\$($HostName)_$($($PSBoundParameters.XCCDFTemplates).Replace("_Manual-xccdf.xml",".ckl"))"
                Write-Verbose "[$($MyInvocation.MyCommand)] Saving to $xccdfNewPath"

                $cklCreated += $xccdfNewPath

                ConvertTo-Checklist -XccdfPath $xccdfTempPath -Destination $xccdfNewPath
                Write-Verbose "[$($MyInvocation.MyCommand)] Created $xccdfNewPath"
            }
            catch {

                Write-Error $_

            }

        }

        # Retrieve Custom Set if provided and create checklists.
        if ($PSBoundParameters.ChecklistSet) {

            Write-Verbose "[$($MyInvocation.MyCommand)] Creating New Checklist from $($PSBoundParameters.ChecklistSet) Set"

            #Declare Config Files with Sets
            $configs = @()

            $configs += $(Get-Content -Raw -Path "$PSScriptRoot\..\..\Toolbx.STIGSupport.config" | ConvertFrom-Json)

            if ($(Test-Path "$env:USERPROFILE\Documents\WindowsPowerShell\Toolbx.STIGSupport.config") -eq $true -eq $true) {
                $configs += $(Get-Content -Raw -Path "$env:USERPROFILE\Documents\WindowsPowerShell\Toolbx.STIGSupport.config" | ConvertFrom-Json)
            }

            foreach ($c in $configs) {

                foreach ($o in $c.NewCheckListOptions) {

                    if ($o.Name -eq $PSBoundParameters.ChecklistSet) {

                        foreach ($ckl in $o.ckl) {

                            Write-Verbose "[$($MyInvocation.MyCommand)] Creating New Checklist $ckl"

                            try {

                                $checklist = $($templates | Where-Object { $_.Name -like "$ckl*" })
                                $xccdfNewPath = "$Destination\$($HostName)_$($($checklist.name).Replace("_Manual-xccdf.xml",".ckl"))"

                                Write-Debug "[$($MyInvocation.MyCommand)] Xccdf: $($checklist.fullname)"
                                Write-Debug "[$($MyInvocation.MyCommand)] SaveTo: $xccdfNewPath"
                                ConvertTo-Checklist -XccdfPath $checklist.fullname -Destination $xccdfNewPath

                                Write-Verbose "[$($MyInvocation.MyCommand)] Created $xccdfNewPath"
                                $cklCreated += $xccdfNewPath

                            }
                            catch {

                                Write-Error $_

                            }

                        }

                    }

                }

            }

        }

        $cklCreated
    }

}