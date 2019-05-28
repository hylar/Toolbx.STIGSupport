Function Export-Checklist {

    [CmdletBinding()]
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
    $XMLSettings.IndentChars = "`t"
    $XMLSettings.NewLineChars = "`n"
    $XMLSettings.Encoding = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList @($false)
    $XMLSettings.ConformanceLevel = [System.Xml.ConformanceLevel]::Document

    $XMLWriter = [System.XML.XMLTextWriter]::Create($Path, $XMLSettings)

    $Global:Test=$Checklist
    $Checklist.InnerXml=$Checklist.InnerXml -replace "&#x0;","[0x00]"
    $Checklist.Save($XMLWriter)
    $XMLWriter.Flush()
    $XMLWriter.Dispose();

}