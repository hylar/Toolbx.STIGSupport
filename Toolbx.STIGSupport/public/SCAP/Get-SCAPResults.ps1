function Get-SCAPResults {

    <#
        .SYNOPSIS
            Get Results from SCAP XCCDF Results.

        .DESCRIPTION
              Get Results from SCAP XCCDF Results.

        .EXAMPLE
            PS C:\>$resluts = Get-SCAPResults -XccdfPath 'C:\Temp\Windows10-SCAP-XCCDF.xml'

            This examples shows calling the command and saving the results to $results.

        .OUTPUTS
            PSOBJECT

        .NOTES
            None
    #>

    Param(

        [Parameter(Mandatory = $true)]
        [ValidateScript( { Test-Path -Path $_ })]
        [string]
        $XccdfPath

    )

    $XCCDF = [XML](Get-Content -Encoding UTF8 -Path $XccdfPath)

    #Grab rule results
    $results = $XCCDF.Benchmark.TestResult.'rule-result'
    $toReturn = @()

    #Loop through them
    foreach ($result in $results) {

        #Get IP
        if ($result.idref -match "(SV-.*_rule)") { $result.idref = $Matches[1] }

        #Return ID and result
        $toReturn += New-Object PSObject -Property @{RuleID = $result.idref; Result = $result.result }

    }

    return $toReturn
}

