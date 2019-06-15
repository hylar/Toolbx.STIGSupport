Function Export-Checklist {

    <#
        .SYNOPSIS
            Export STIG Checklist

        .DESCRIPTION
            Export STIG Checklist

        .EXAMPLE
            PS C:\> Export-Checklist -Checklist $CKL -path C:\Temp\U_Windows10.ckl

            This example shows how to Export a checklist. $CKL is passed with the xml data and then it is saved to the location listed in Path.

        .OUTPUTS
            [XML]

        .NOTES
            None
    #>

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

    $Checklist.InnerXml = $Checklist.InnerXml -replace "&#x0;", "[0x00]"

    $Checklist.Save($XMLWriter)
    $XMLWriter.Flush()
    $XMLWriter.Dispose();

}