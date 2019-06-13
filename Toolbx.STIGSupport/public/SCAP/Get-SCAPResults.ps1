

function Get-SCAPResults {

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

