Function Set-VulnIDFinding
{
    [CmdletBinding()]
    Param
    (
        # Specify the Checklist to update.
        [Parameter(Mandatory=$true, ValueFromPipeline = $true)]
        [XML]
        $Checklist,

        # Specify the STIG VulnID
        [Parameter(Mandatory=$true, ValueFromPipeline = $true)]
        [String]
        $VulnID,

        # Specify the STIG Rule ID
        [Parameter(ValueFromPipeline = $true)]
        [String]
        $RuleID,

        # Specify the Details to update.
        [Parameter(ValueFromPipeline = $true)]
        [String]
        $Details,

        # Specify Comments to update.
        [Parameter(ValueFromPipeline = $true)]
        [String]
        $Comments,

        [Parameter(Mandatory=$true, ValueFromPipeline = $true)]
        [ValidateSet("Open","NotAFinding","Not_Reviewed","Not_Applicable")]
        [String]
        $Status
    )

    If ($PSBoundParameters.ContainsKey('RuleID') -and $RuleID -ne '') {

        Write-Verbose "[Set-VulnIDFinding] Entered RuleID Check '$RuleID'"
        Set-VulnIDFindingAttribute -Checklist $Checklist -RuleID $RuleID -VulnID $VulnID -Attribute "STATUS"  -Value $Status

        # Update Details if passed.
        If($PSBoundParameters.ContainsKey('Details')){
            Set-VulnIDFindingAttribute -Checklist $Checklist -RuleID $RuleID -VulnID $VulnID -Attribute "FINDING_DETAILS"  -Value "$Details"
        }

        # Update Comments if passed.
        If($PSBoundParameters.ContainsKey('Comments')){
            Set-VulnIDFindingAttribute -Checklist $Checklist -RuleID $RuleID -VulnID $VulnID -Attribute "COMMENTS"  -Value "$Comments"
        }

    }
    else {

        Set-VulnIDFindingAttribute -Checklist $Checklist -VulnID $VulnID -Attribute "STATUS"  -Value "$Status"

        # Update Details if passed.
        If($PSBoundParameters.ContainsKey('Details')){
            Set-VulnIDFindingAttribute -Checklist $Checklist -VulnID $VulnID -Attribute "FINDING_DETAILS"  -Value "$Details"
        }

        # Update Comments if passed.
        If($PSBoundParameters.ContainsKey('Comments')){
            Set-VulnIDFindingAttribute -Checklist $Checklist -VulnID $VulnID -Attribute "COMMENTS"  -Value "$Comments"
        }

    }

}