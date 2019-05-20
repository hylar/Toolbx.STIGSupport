Function Export-Checklist {

    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [XML]
        $Checklist,

        [Parameter(Mandatory = $true)]
        [string]
        $Path
    )

    $XMLSettings = New-Object -TypeName System.XML.XMLWriterSettings
    $XMLSettings.Indent = $true;
    $XMLSettings.IndentChars = "    "
    $XMLSettings.NewLineChars = "`n"

    $XMLWriter = [System.XML.XMLTextWriter]::Create($Path, $XMLSettings)

    $Checklist.Save($XMLWriter)
    $XMLWriter.Dispose();

}