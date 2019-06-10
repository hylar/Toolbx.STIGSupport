Function Import-Checklist {

    <#
        .SYNOPSIS
            Import STIG Checklist

        .DESCRIPTION
            Import STIG Checklist

        .EXAMPLE
            PS C:\> $ckl = Import-Checklist -path C:\Temp\U_Windows10.ckl

            This example shows how to import a checklist.

        .OUTPUTS
            [XML]

        .NOTES
            None
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateScript( {Test-Path -Path $_})]
        [string]
        $Path
    )

    return [XML](Get-Content -Path $Path)

}
