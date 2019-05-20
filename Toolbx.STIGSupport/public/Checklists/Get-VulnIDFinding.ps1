Function Get-VulnIDFinding {

    [CmdletBinding()]
    Param(

        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [XML]
        $Checklist,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [String]
        $VulnID

    )

    [PSCustomObject]@{
        VulnID        = $VulnID
        Status        = Get-VulnIDFindingAttribute -Checklist $Checklist -VulnId $VulnID -Attribute "STATUS"
        Override      = Get-VulnIDFindingAttribute -Checklist $Checklist -VulnId $VulnID -Attribute "SEVERITY_OVERRIDE"
        Justification = Get-VulnIDFindingAttribute -Checklist $Checklist -VulnId $VulnID -Attribute "SEVERITY_JUSTIFICATION"
        Finding       = Get-VulnIDFindingAttribute -Checklist $Checklist -VulnId $VulnID -Attribute "FINDING_DETAILS"
        Comments      = Get-VulnIDFindingAttribute -Checklist $Checklist -VulnId $VulnID -Attribute "COMMENTS"
    }

}
