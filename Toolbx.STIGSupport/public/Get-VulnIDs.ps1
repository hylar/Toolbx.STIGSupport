Function Get-VulnIDs {

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [XML]
        $Checklist
    )

    $vulIds = @() + (Select-XML -Xml $Checklist -XPath "//STIG_DATA[VULN_ATTRIBUTE='Vuln_Num']").Node.ATTRIBUTE_DATA

    $vulIds

}