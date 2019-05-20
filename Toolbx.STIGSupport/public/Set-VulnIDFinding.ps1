Function Set-VulnIDFinding
{
    Param
    (
        [Parameter(Mandatory=$true, ValueFromPipeline = $true)]
        [XML]
        $Checklist,

        [Parameter(Mandatory=$true, ValueFromPipeline = $true)]
        [String]
        $VulnID,

        [Parameter(ValueFromPipeline = $true)]
        [String]
        $Details,

        [Parameter(ValueFromPipeline = $true)]
        [String]
        $Comments,

        [Parameter(Mandatory=$true, ValueFromPipeline = $true)]
        [ValidateSet("Open","NotAFinding","Not_Reviewed","Not_Applicable")]
        [String]
        $Status
    )

    Set-VulnIDFindingAttribute -Checklist $Checklist -VulnID $VulnID -Attribute "STATUS"  -Value "$Status"
    Set-VulnIDFindingAttribute -Checklist $Checklist -VulnID $VulnID -Attribute "FINDING_DETAILS"  -Value "$Details"
    Set-VulnIDFindingAttribute -Checklist $Checklist -VulnID $VulnID -Attribute "COMMENTS"  -Value "$Comments"

}