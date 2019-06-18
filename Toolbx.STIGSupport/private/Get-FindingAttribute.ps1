
function Get-FindingAttribute {

    <#
        .SYNOPSIS
            Get specific Attributes for STIG Check.

        .DESCRIPTION
            This is a private function to help with getting STIG check attributes.

        .EXAMPLE
            PS C:\>

        .EXAMPLE
            PS C:\>

        .OUTPUTS
            None

        .NOTES
            None
    #>

    Param(

        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [XML]
        $Checklist,

        [Parameter(ValueFromPipeline = $true)]
        [String]
        $VulnID,

        [Parameter(ValueFromPipeline = $true)]
        [String]
        $RuleID,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateSet(
            "Rule_ID",
            "Severity",
            "Check_Content",
            "Fix_Text",
            "SEVERITY_JUSTIFICATION",
            "SEVERITY_OVERRIDE",
            "COMMENTS",
            "FINDING_DETAILS",
            "STATUS"
        )]
        $Attribute

    )

    try {

        If ($PSBoundParameters.ContainsKey('RuleID') -and $RuleID -ne '') {

            $toReturn = (Select-XML -Xml $Checklist -XPath "//STIG_DATA[VULN_ATTRIBUTE='Rule_ID' and ATTRIBUTE_DATA='$RuleID']").Node.ParentNode.SelectNodes("descendant::STIG_DATA[VULN_ATTRIBUTE='$Attribute']").Attribute_Data

            if ($null -eq $ToReturn) {
                $toReturn = (Select-XML -Xml $Checklist -XPath "//STIG_DATA[VULN_ATTRIBUTE='Rule_Ver' and ATTRIBUTE_DATA='$RuleID']").Node.ParentNode.SelectNodes("descendant::STIG_DATA[VULN_ATTRIBUTE='$Attribute']").Attribute_Data
            }

        }
        else {

            $toReturn = (Select-XML -Xml $Checklist -XPath "//STIG_DATA[VULN_ATTRIBUTE='Vuln_Num' and ATTRIBUTE_DATA='$VulnID']").Node.ParentNode.SelectNodes("descendant::STIG_DATA[VULN_ATTRIBUTE='$Attribute']").Attribute_Data
        }

        $toReturn

    }
    catch {

        $PSCmdlet.ThrowTerminatingError( $_ )

    }

}