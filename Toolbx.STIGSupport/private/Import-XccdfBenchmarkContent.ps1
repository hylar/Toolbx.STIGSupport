function Import-XccdfBenchmarkContent {

    [CmdletBinding()]
    [OutputType([xml])]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Path
    )

    if (-not (Test-Path -Path $Path)) { Throw "The file $Path was not found" }

    [xml] $xccdfXmlContent = Get-Content -Path $Path -Encoding UTF8

    $xccdfXmlContent.Benchmark
}