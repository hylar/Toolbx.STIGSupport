Function ConvertTo-Checklist {

    <#
        .SYNOPSIS
            Creates new STIG Checklists from DISA XCCDF file.

        .DESCRIPTION
            Creates new STIG Checklists from DISA XCCDF file.

        .EXAMPLE
            PS C:\> ConvertTo-Checklist -XccdfPath 'C:\Temp\U_Adobe_Acrobat_Reader_DC_Continuous_V1R5_Manual-xccdf.xml -Destination C:\Temp\U_Adobe_Acrobat_Reader_DC_Continuous_.ckl

            This examples shows the function created an adobe reader checklist in C:\Temp.

        .OUTPUTS
            None

        .NOTES
            None
    #>

    [CmdletBinding()]
    param(

        # Specify the path to the DISA XCCDF file.
        [Parameter(Mandatory = $true)]
        [ValidateScript( {Test-Path -Path $_})]
        [string]
        $XccdfPath,

        # Specify the path to save the new checklist (.ckl) file.
        [Parameter(Mandatory = $true)]
        [string]
        $Destination,

        # Specify the host name for the checklist.
        [Parameter()]
        [string]
        $HostName,

        # Specify the Host IP Address for the checklist.
        [Parameter()]
        [string]
        $HostIP,

        # Specify the Host GUID for the checklist.
        [Parameter()]
        [string]
        $HostGUID,

        # Specify the Host MAC Address for the checklist.
        [Parameter()]
        [string]
        $HostMAC,

        # Specify the Host FQDN for the checklist.
        [Parameter()]
        [string]
        $HostFQDN
    )

    begin{

        function Get-VulnerabilityList {
            [CmdletBinding()]
            [OutputType([xml])]
            param
            (
                [Parameter()]
                [psobject]
                $XccdfBenchmark
            )

            [System.Collections.ArrayList] $vulnerabilityList = @()

            foreach ( $vulnerability in $XccdfBenchmark.Group ) {

                [xml]$vulnerabiltyDiscussionElement = "<discussionroot>$([System.Security.SecurityElement]::Escape($vulnerability.Rule.description))</discussionroot>"

                [void] $vulnerabilityList.Add(
                    @(
                        [PSCustomObject]@{ Name = 'Vuln_Num'; Value = $vulnerability.id },
                        [PSCustomObject]@{ Name = 'Severity'; Value = $vulnerability.Rule.severity },
                        [PSCustomObject]@{ Name = 'Group_Title'; Value = $vulnerability.title },
                        [PSCustomObject]@{ Name = 'Rule_ID'; Value = $vulnerability.Rule.id },
                        [PSCustomObject]@{ Name = 'Rule_Ver'; Value = $vulnerability.Rule.version },
                        [PSCustomObject]@{ Name = 'Rule_Title'; Value = $vulnerability.Rule.title },
                        [PSCustomObject]@{ Name = 'Vuln_Discuss'; Value = $vulnerabiltyDiscussionElement.discussionroot.VulnDiscussion },
                        [PSCustomObject]@{ Name = 'IA_Controls'; Value = $vulnerabiltyDiscussionElement.discussionroot.IAControls },
                        [PSCustomObject]@{ Name = 'Check_Content'; Value = $vulnerability.Rule.check.'check-content' },
                        [PSCustomObject]@{ Name = 'Fix_Text'; Value = $vulnerability.Rule.fixtext.InnerText },
                        [PSCustomObject]@{ Name = 'False_Positives'; Value = $vulnerabiltyDiscussionElement.discussionroot.FalsePositives },
                        [PSCustomObject]@{ Name = 'False_Negatives'; Value = $vulnerabiltyDiscussionElement.discussionroot.FalseNegatives },
                        [PSCustomObject]@{ Name = 'Documentable'; Value = $vulnerabiltyDiscussionElement.discussionroot.Documentable },
                        [PSCustomObject]@{ Name = 'Mitigations'; Value = $vulnerabiltyDiscussionElement.discussionroot.Mitigations },
                        [PSCustomObject]@{ Name = 'Potential_Impact'; Value = $vulnerabiltyDiscussionElement.discussionroot.PotentialImpacts },
                        [PSCustomObject]@{ Name = 'Third_Party_Tools'; Value = $vulnerabiltyDiscussionElement.discussionroot.ThirdPartyTools },
                        [PSCustomObject]@{ Name = 'Mitigation_Control'; Value = $vulnerabiltyDiscussionElement.discussionroot.MitigationControl },
                        [PSCustomObject]@{ Name = 'Responsibility'; Value = $vulnerabiltyDiscussionElement.discussionroot.Responsibility },
                        [PSCustomObject]@{ Name = 'Security_Override_Guidance'; Value = $vulnerabiltyDiscussionElement.discussionroot.SeverityOverrideGuidance },
                        [PSCustomObject]@{ Name = 'Check_Content_Ref'; Value = $vulnerability.Rule.check.'check-content-ref'.href },
                        [PSCustomObject]@{ Name = 'Weight'; Value = $vulnerability.Rule.Weight },
                        [PSCustomObject]@{ Name = 'Class'; Value = 'Unclass' },
                        [PSCustomObject]@{ Name = 'STIGRef'; Value = "$($XccdfBenchmark.title) :: $($XccdfBenchmark.'plain-text'.InnerText)" },
                        [PSCustomObject]@{ Name = 'TargetKey'; Value = $vulnerability.Rule.reference.identifier }

                        # Some Stigs have multiple Control Correlation Identifiers (CCI)
                        $(
                            # Extract only the cci entries
                            $CCIREFList = $vulnerability.Rule.ident |
                            Where-Object { $PSItem.system -eq 'http://iase.disa.mil/cci' } |
                            Select-Object 'InnerText' -ExpandProperty 'InnerText'

                            foreach ($CCIREF in $CCIREFList) {
                                [PSCustomObject]@{ Name = 'CCI_REF'; Value = $CCIREF }
                            }
                        )
                    )
                )
            }

            return $vulnerabilityList
        }

    }

    Process{

        $xccdfBenchmarkContent = $([XML](Get-Content -Encoding UTF8 -Path $XccdfPath)).Benchmark

        $xmlWriterSettings = [System.Xml.XmlWriterSettings]::new()
        $xmlWriterSettings.Indent = $true
        $xmlWriterSettings.IndentChars = "`t"
        $xmlWriterSettings.NewLineChars = "`n"
        $writer = [System.Xml.XmlWriter]::Create($Destination, $xmlWriterSettings)


        $writer.WriteComment("Created by Toolbx.STIGSupport ($((Get-Module Toolbx.STIGSupport).Version.ToString()))")

        $writer.WriteStartElement('CHECKLIST')

        $writer.WriteStartElement("ASSET")

        $assetElements = [ordered] @{
            'ROLE'            = 'None'
            'ASSET_TYPE'      = 'Computing'
            'HOST_NAME'       = "$HostName"
            'HOST_IP'         = "$HostIP"
            'HOST_MAC'        = "$HostMAC"
            'HOST_GUID'       = "$HostGUID"
            'HOST_FQDN'       = "$HostFQDN"
            'TECH_AREA'       = ''
            'TARGET_KEY'      = '2350'
            'WEB_OR_DATABASE' = 'false'
            'WEB_DB_SITE'     = ''
            'WEB_DB_INSTANCE' = ''
        }

        foreach ($assetElement in $assetElements.GetEnumerator()) {
            $writer.WriteStartElement($assetElement.name)
            $writer.WriteString($assetElement.value)
            $writer.WriteEndElement()
        }

        $writer.WriteEndElement(<#ASSET#>)

        $writer.WriteStartElement("STIGS")
        $writer.WriteStartElement("iSTIG")
        $writer.WriteStartElement("STIG_INFO")

        $StigInfoElements = [ordered] @{
            'version'        = $xccdfBenchmarkContent.version
            'classification' = 'UNCLASSIFIED'
            'customname'     = ''
            'stigid'         = $xccdfBenchmarkContent.id
            'description'    = $xccdfBenchmarkContent.description
            'filename'       = Split-Path -Path $XccdfPath -Leaf
            'releaseinfo'    = $xccdfBenchmarkContent.'plain-text'.InnerText
            'title'          = $xccdfBenchmarkContent.title
            'uuid'           = (New-Guid).Guid
            'notice'         = $xccdfBenchmarkContent.notice.InnerText
            'source'         = $xccdfBenchmarkContent.reference.source
        }

        foreach ($StigInfoElement in $StigInfoElements.GetEnumerator()){

            $writer.WriteStartElement("SI_DATA")

            $writer.WriteStartElement('SID_NAME')
            $writer.WriteString($StigInfoElement.name)
            $writer.WriteEndElement(<#SID_NAME#>)

            $writer.WriteStartElement('SID_DATA')
            $writer.WriteString($StigInfoElement.value)
            $writer.WriteEndElement(<#SID_DATA#>)

            $writer.WriteEndElement(<#SI_DATA#>)

        }

        $writer.WriteEndElement(<#STIG_INFO#>)

        foreach ( $vulnerability in (Get-VulnerabilityList -XccdfBenchmark $xccdfBenchmarkContent) )
        {
            $writer.WriteStartElement("VULN")

            foreach ($attribute in $vulnerability.GetEnumerator())
            {
                $status   = 'Not_Reviewed'
                $comments = $null
                $findings = $null

                $writer.WriteStartElement("STIG_DATA")

                $writer.WriteStartElement("VULN_ATTRIBUTE")
                $writer.WriteString($attribute.Name)
                $writer.WriteEndElement(<#VULN_ATTRIBUTE#>)

                $writer.WriteStartElement("ATTRIBUTE_DATA")
                $writer.WriteString($attribute.Value)
                $writer.WriteEndElement(<#ATTRIBUTE_DATA#>)

                $writer.WriteEndElement(<#STIG_DATA#>)
            }

            $writer.WriteStartElement("STATUS")
            $writer.WriteString($status)
            $writer.WriteEndElement(<#STATUS#>)

            $writer.WriteStartElement("FINDING_DETAILS")
            $writer.WriteString($findings)
            $writer.WriteEndElement(<#FINDING_DETAILS#>)

            $writer.WriteStartElement("COMMENTS")
            $writer.WriteString($comments)
            $writer.WriteEndElement(<#COMMENTS#>)

            $writer.WriteStartElement("SEVERITY_OVERRIDE")
            $writer.WriteString('')
            $writer.WriteEndElement(<#SEVERITY_OVERRIDE#>)

            $writer.WriteStartElement("SEVERITY_JUSTIFICATION")
            $writer.WriteString('')
            $writer.WriteEndElement(<#SEVERITY_JUSTIFICATION#>)

            $writer.WriteEndElement(<#VULN#>)
        }

        $writer.WriteEndElement(<#iSTIG#>)
        $writer.WriteEndElement(<#STIGS#>)
        $writer.WriteEndElement(<#CHECKLIST#>)
        $writer.Flush()
        $writer.Close()

    }

}