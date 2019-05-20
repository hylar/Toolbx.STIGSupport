Function Merge-Checklist {

    Param(

        [Parameter(Mandatory=$true)]
        [String]
        $SourceChecklist,

        [Parameter(Mandatory=$true)]
        [String]
        $DestinationChecklist

    )

    #TODO: Create section to copy host data.

    $source = Import-Checklist -Path $SourceChecklist
    $destination = Import-Checklist -Path $DestinationChecklist

    $srcVulnIds = Get-VulnIDs -Checklist $source

    Get-VulnIDs -Checklist $destination | ForEach-Object {

        if($srcVulnIds.Contains($_)){

            $tmp = Get-VulnIDFinding -Checklist $source -VulnID $_

            # Set new checklist, If its empty it will set an empty string.
            Set-VulnIDFindingAttribute -Checklist $destination -VulnID $_ -Attribute "STATUS"  -Value "$($tmp.Status)"
            Set-VulnIDFindingAttribute -Checklist $destination -VulnID $_ -Attribute "SEVERITY_OVERRIDE"  -Value "$($tmp.Override)"
            Set-VulnIDFindingAttribute -Checklist $destination -VulnID $_ -Attribute "SEVERITY_JUSTIFICATION"  -Value "$($tmp.Justification)"
            Set-VulnIDFindingAttribute -Checklist $destination -VulnID $_ -Attribute "FINDING_DETAILS"  -Value "$($tmp.Finding)"
            Set-VulnIDFindingAttribute -Checklist $destination -VulnID $_ -Attribute "COMMENTS"  -Value "$($tmp.Comments)"
        }

        #TODO: Add Else Block to track items that wernt merged.

    }

    Export-Checklist -Checklist $destination -Path $DestinationChecklist

}