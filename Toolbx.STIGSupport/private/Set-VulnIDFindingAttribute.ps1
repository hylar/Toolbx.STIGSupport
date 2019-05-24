
function Set-VulnIDFindingAttribute {

    Param(

        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [XML]
        $Checklist,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [String]
        $VulnID,

        [Parameter(ValueFromPipeline = $true)]
        [String]
        $RuleID,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateSet(
            "SEVERITY_JUSTIFICATION",
            "SEVERITY_OVERRIDE",
            "COMMENTS",
            "FINDING_DETAILS",
            "STATUS"
        )]
        $Attribute,

        [Parameter(ValueFromPipeline = $true)]
        [string]
        $Value
    )

    try {

        If ($PSBoundParameters.ContainsKey('RuleID') -and $RuleID -ne '') {

            $xObject = (Select-XML -Xml $Checklist -XPath "//STIG_DATA[VULN_ATTRIBUTE='Rule_ID' and ATTRIBUTE_DATA='$RuleID']").Node.ParentNode

            $xObject | ForEach-Object { $_.$Attribute = [System.Security.SecurityElement]::Escape($Value) }

        }
        else {

            $xObject = (Select-XML -Xml $Checklist -XPath "//STIG_DATA[VULN_ATTRIBUTE='Vuln_Num' and ATTRIBUTE_DATA='$VulnID']").Node.ParentNode

            $xObject | ForEach-Object { $_.$Attribute = [System.Security.SecurityElement]::Escape($Value) }

        }

    }
    catch {

        $PSCmdlet.ThrowTerminatingError( $_ )

    }

}