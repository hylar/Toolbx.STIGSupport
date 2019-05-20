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

        [String]
        $Details,

        [String]
        $Comments,

        [Parameter(Mandatory=$true, ValueFromPipeline = $true)]
        [ValidateSet(
            “Open”,
            ”NotAFinding”,
            "Not_Reviewed",
            "Not_Applicable"
        )]
        [String]
        $Status
    )

    Set-VulnIDFindingAttribute -Checklist $Checklist -VulnID $_ -Attribute "STATUS"  -Value "$Status"
    Set-VulnIDFindingAttribute -Checklist $Checklist -VulnID $_ -Attribute "FINDING_DETAILS"  -Value "$Details"
    Set-VulnIDFindingAttribute -Checklist $Checklist -VulnID $_ -Attribute "COMMENTS"  -Value "$Comments"

}