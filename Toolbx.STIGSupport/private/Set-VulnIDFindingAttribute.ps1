
function Set-VulnIDFindingAttribute {

    Param(

        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [XML]
        $Checklist,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [String]
        $VulnID,

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

        ((Select-XML -Xml $Checklist -XPath "//STIG_DATA[VULN_ATTRIBUTE='Vuln_Num' and ATTRIBUTE_DATA='$VulnID']").Node.ParentNode).$Attribute = $Value

    }
    catch {

        $PSCmdlet.ThrowTerminatingError( $_ )

    }

}