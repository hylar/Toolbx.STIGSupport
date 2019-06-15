
function Set-FindingAttribute {

    <#
        .SYNOPSIS
            Set specific Attributes for STIG Check.

        .DESCRIPTION
            This is a private function to help with setting STIG check attributes.

        .EXAMPLE
            PS C:\> Set-FindingAttribute -Checklist $Ckl -VulnID "V-46481" -Attribute "STATUS" -Value "Open"

            This example shows to set an attribute based on the VulnID.

        .EXAMPLE
            PS C:\> Set-FindingAttribute -Checklist $Ckl -RuleID "SV-59345r1_rule" -Attribute "STATUS" -Value "Not_Reviewed"

            This example shows how to set an attribute based on the RuleID.

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